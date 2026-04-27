from __future__ import annotations

import argparse
import ipaddress
import time
from pathlib import Path

from .models import SeenDevice, utc_now
from .render import export_devices, print_devices, print_history, print_summary, stderr
from .scanner import DEFAULT_TIMEOUT_MS, DEFAULT_WORKERS, detect_networks, scan_network, vendor_from_mac
from .store import DeviceStore, default_db_path


MAX_HOSTS_WITHOUT_CONFIRM = 4096


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscan",
        description="Scan the local network and keep track of devices as they move between IP addresses.",
    )
    parser.add_argument("--db", type=Path, default=default_db_path(), help="SQLite database path.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a CIDR range and record online devices.")
    add_scan_arguments(scan)

    watch = subparsers.add_parser("watch", help="Scan repeatedly and keep the table fresh.")
    add_scan_arguments(watch)
    watch.add_argument("--interval", type=int, default=60, help="Seconds between scans.")
    watch.add_argument("--count", type=int, default=0, help="Number of scans to run. 0 means forever.")

    devices = subparsers.add_parser("devices", help="Show tracked devices from the local database.")
    devices.add_argument("--status", choices=["all", "online", "offline"], default="all")

    history = subparsers.add_parser("history", help="Show recent sightings.")
    history.add_argument("--limit", type=int, default=30)

    export = subparsers.add_parser("export", help="Export tracked devices to CSV or JSON.")
    export.add_argument("path", type=Path)
    export.add_argument("--format", choices=["csv", "json"], default=None)
    export.add_argument("--status", choices=["all", "online", "offline"], default="all")

    forget = subparsers.add_parser("forget", help="Remove a tracked device by ID.")
    forget.add_argument("device_id", type=int)

    networks = subparsers.add_parser("networks", help="Show detected local network ranges.")
    networks.set_defaults(command="networks")

    return parser


def add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("cidr", nargs="?", default="auto", help="CIDR to scan, for example 192.168.1.0/24.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_MS, help="Ping timeout in milliseconds.")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Concurrent ping workers.")
    parser.add_argument("--no-names", action="store_true", help="Skip reverse DNS hostname lookup.")
    parser.add_argument(
        "--offline-after",
        type=int,
        default=10,
        help="Mark devices offline when not seen for this many minutes.",
    )
    parser.add_argument(
        "--allow-large",
        action="store_true",
        help=f"Allow scans larger than {MAX_HOSTS_WITHOUT_CONFIRM} hosts.",
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "networks":
        return command_networks()

    store = DeviceStore(args.db)
    try:
        if args.command == "scan":
            return command_scan(args, store)
        if args.command == "watch":
            return command_watch(args, store)
        if args.command == "devices":
            print_devices(store.devices(args.status), "Tracked devices")
            return 0
        if args.command == "history":
            print_history(store.history(args.limit))
            return 0
        if args.command == "export":
            devices = store.devices(args.status)
            file_format = args.format or args.path.suffix.lstrip(".").lower() or "csv"
            if file_format not in {"csv", "json"}:
                stderr("Export format must be csv or json.")
                return 2
            export_devices(devices, args.path, file_format)
            print(f"Exported {len(devices)} devices to {args.path}")
            return 0
        if args.command == "forget":
            removed = store.forget(args.device_id)
            print("Device removed." if removed else "No device found with that ID.")
            return 0 if removed else 1
    finally:
        store.close()

    parser.print_help()
    return 2


def command_networks() -> int:
    networks = detect_networks()
    if not networks:
        stderr("No local IPv4 networks were detected. Pass a CIDR explicitly, for example: netscan scan 192.168.1.0/24")
        return 1
    for network in networks:
        gateway = f", gateway {network.gateway}" if network.gateway else ""
        print(f"{network.cidr} ({network.address}, mask {network.mask}{gateway}, via {network.source})")
    return 0


def command_scan(args: argparse.Namespace, store: DeviceStore) -> int:
    cidr = resolve_cidr(args.cidr)
    if cidr is None:
        return 1
    network = ipaddress.ip_network(cidr, strict=False)
    scanned_hosts = host_count(network)
    if scanned_hosts > MAX_HOSTS_WITHOUT_CONFIRM and not args.allow_large:
        stderr(
            f"{cidr} contains {scanned_hosts} usable hosts. "
            f"Use --allow-large if you really want to scan that range."
        )
        return 2

    started = utc_now()
    seen = enrich_devices(
        scan_network(
            cidr,
            timeout_ms=args.timeout,
            workers=args.workers,
            resolve_names=not args.no_names,
        )
    )
    result = store.record_scan(
        cidr=cidr,
        scanned_hosts=scanned_hosts,
        seen_devices=seen,
        started_at=started,
        offline_after_minutes=args.offline_after,
    )
    print_summary(result.summary)
    print_devices(result.devices, "Online devices")
    return 0


def command_watch(args: argparse.Namespace, store: DeviceStore) -> int:
    cidr = resolve_cidr(args.cidr)
    if cidr is None:
        return 1
    network = ipaddress.ip_network(cidr, strict=False)
    scanned_hosts = host_count(network)
    if scanned_hosts > MAX_HOSTS_WITHOUT_CONFIRM and not args.allow_large:
        stderr(
            f"{cidr} contains {scanned_hosts} usable hosts. "
            f"Use --allow-large if you really want to scan that range."
        )
        return 2

    iteration = 0
    while True:
        iteration += 1
        print(f"\nScan {iteration} at {utc_now().isoformat().replace('+00:00', 'Z')}")
        started = utc_now()
        seen = enrich_devices(
            scan_network(
                cidr,
                timeout_ms=args.timeout,
                workers=args.workers,
                resolve_names=not args.no_names,
            )
        )
        result = store.record_scan(
            cidr=cidr,
            scanned_hosts=scanned_hosts,
            seen_devices=seen,
            started_at=started,
            offline_after_minutes=args.offline_after,
        )
        print_summary(result.summary)
        print_devices(store.devices("all"), "Tracked devices")
        if args.count and iteration >= args.count:
            return 0
        time.sleep(max(1, args.interval))


def resolve_cidr(value: str) -> str | None:
    if value != "auto":
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            stderr(f"Invalid CIDR: {exc}")
            return None
    networks = detect_networks()
    if not networks:
        stderr("Could not detect a local network. Pass a CIDR explicitly, for example: netscan scan 192.168.1.0/24")
        return None
    return networks[0].cidr


def enrich_devices(devices: list[SeenDevice]) -> list[SeenDevice]:
    return [
        SeenDevice(
            ip=device.ip,
            hostname=device.hostname,
            mac=device.mac,
            vendor=vendor_from_mac(device.mac),
            latency_ms=device.latency_ms,
            source=device.source,
        )
        for device in devices
    ]


def host_count(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> int:
    if network.num_addresses <= 2:
        return network.num_addresses
    return network.num_addresses - 2
