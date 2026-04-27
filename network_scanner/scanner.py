from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable

from .models import SeenDevice


DEFAULT_TIMEOUT_MS = 700
DEFAULT_WORKERS = 128


@dataclass(frozen=True)
class LocalNetwork:
    address: str
    mask: str
    gateway: str | None
    cidr: str
    source: str


def normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2)).upper()


def detect_networks() -> list[LocalNetwork]:
    if platform.system().lower() == "windows":
        networks = _detect_windows_networks()
        if networks:
            return networks
    fallback = _detect_socket_network()
    return [fallback] if fallback else []


def _detect_socket_network() -> LocalNetwork | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.2)
        sock.connect(("8.8.8.8", 80))
        address = sock.getsockname()[0]
    except OSError:
        try:
            address = socket.gethostbyname(socket.gethostname())
        except OSError:
            return None
    finally:
        try:
            sock.close()
        except UnboundLocalError:
            pass
    if not address or address.startswith("127."):
        return None
    network = ipaddress.ip_network(f"{address}/24", strict=False)
    return LocalNetwork(address, "255.255.255.0", None, str(network), "socket-fallback")


def _detect_windows_networks() -> list[LocalNetwork]:
    try:
        result = subprocess.run(
            ["ipconfig"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    blocks = re.split(r"\r?\n\r?\n", result.stdout)
    networks: list[LocalNetwork] = []
    for block in blocks:
        if "IPv4" not in block or "Subnet Mask" not in block:
            continue
        ip_match = re.search(r"IPv4 Address[.\s]*:\s*([0-9.]+)", block)
        mask_match = re.search(r"Subnet Mask[.\s]*:\s*([0-9.]+)", block)
        gateway_match = re.search(r"Default Gateway[.\s]*:\s*([0-9.]+)", block)
        if not ip_match or not mask_match:
            continue
        address = ip_match.group(1)
        mask = mask_match.group(1)
        if address.startswith(("127.", "169.254.")):
            continue
        try:
            network = ipaddress.ip_network(f"{address}/{mask}", strict=False)
        except ValueError:
            continue
        networks.append(
            LocalNetwork(
                address=address,
                mask=mask,
                gateway=gateway_match.group(1) if gateway_match else None,
                cidr=str(network),
                source="ipconfig",
            )
        )
    return _dedupe_networks(networks)


def _dedupe_networks(networks: Iterable[LocalNetwork]) -> list[LocalNetwork]:
    seen: set[str] = set()
    result: list[LocalNetwork] = []
    for network in networks:
        if network.cidr in seen:
            continue
        seen.add(network.cidr)
        result.append(network)
    return result


def get_arp_table() -> dict[str, str]:
    try:
        result = subprocess.run(
            ["arp", "-a"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    return parse_arp_table(result.stdout)


def parse_arp_table(output: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in output.splitlines():
        ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        mac_match = re.search(r"\b([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\b", line)
        if not ip_match or not mac_match:
            continue
        try:
            ipaddress.ip_address(ip_match.group(1))
        except ValueError:
            continue
        mac = normalize_mac(mac_match.group(1))
        if mac:
            entries[ip_match.group(1)] = mac
    return entries


def scan_network(
    cidr: str,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    workers: int = DEFAULT_WORKERS,
    resolve_names: bool = True,
) -> list[SeenDevice]:
    network = ipaddress.ip_network(cidr, strict=False)
    targets = [str(ip) for ip in network.hosts()]
    if not targets:
        targets = [str(network.network_address)]

    alive: dict[str, float | None] = {}
    max_workers = max(1, min(workers, len(targets)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping, ip, timeout_ms): ip for ip in targets}
        for future in as_completed(futures):
            ip = futures[future]
            latency = future.result()
            if latency is not None:
                alive[ip] = latency

    arp_table = get_arp_table()
    for ip in arp_table:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if address in network:
            alive.setdefault(ip, None)

    devices: list[SeenDevice] = []
    for ip, latency in sorted(alive.items(), key=lambda item: ipaddress.ip_address(item[0])):
        hostname = resolve_hostname(ip) if resolve_names else None
        has_mac = ip in arp_table
        devices.append(
            SeenDevice(
                ip=ip,
                hostname=hostname,
                mac=arp_table.get(ip),
                latency_ms=latency,
                source="icmp+arp" if latency is not None and has_mac else "arp-cache" if has_mac else "icmp",
            )
        )
    return devices


def ping(ip: str, timeout_ms: int) -> float | None:
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        timeout_s = max(1, round(timeout_ms / 1000))
        command = ["ping", "-c", "1", "-W", str(timeout_s), ip]

    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(1.0, timeout_ms / 1000 + 1.0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return round((time.perf_counter() - started) * 1000, 1)


def resolve_hostname(ip: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except (OSError, socket.herror):
        hostname = None
    if hostname:
        return hostname.rstrip(".") or None
    if platform.system().lower() == "windows":
        return resolve_netbios_name(ip)
    return None


def resolve_netbios_name(ip: str) -> str | None:
    try:
        result = subprocess.run(
            ["nbtstat", "-A", ip],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in result.stdout.splitlines():
        match = re.match(r"\s*([A-Za-z0-9_.-]{1,15})\s+<00>\s+UNIQUE", line, flags=re.IGNORECASE)
        if match:
            name = match.group(1).strip()
            if name and name.upper() != "WORKGROUP":
                return name
    return None


def vendor_from_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    prefixes = {
        "00:05:69": "VMware",
        "00:0C:29": "VMware",
        "00:1C:42": "Parallels",
        "00:1D:D8": "Microsoft",
        "00:50:56": "VMware",
        "08:00:27": "VirtualBox",
        "28:16:AD": "Intel",
        "3C:22:FB": "Apple",
        "44:65:0D": "Amazon",
        "B8:27:EB": "Raspberry Pi",
        "BC:24:11": "Proxmox",
        "DC:A6:32": "Raspberry Pi",
        "F4:5C:89": "Apple",
    }
    return prefixes.get(mac[:8])
