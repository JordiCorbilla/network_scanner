from __future__ import annotations

import csv
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable

from .models import ScanSummary, TrackedDevice, format_time

try:
    from rich import box
    from rich.console import Console
    from rich.table import Table
except ImportError:  # pragma: no cover - optional dependency
    box = None
    Console = None
    Table = None


def print_devices(devices: list[TrackedDevice], title: str = "Devices") -> None:
    if Console and Table:
        _print_devices_rich(devices, title)
        return
    _print_devices_plain(devices, title)


def print_summary(summary: ScanSummary) -> None:
    text = (
        f"Scanned {summary.scanned_hosts} hosts in {summary.cidr}. "
        f"Online: {summary.alive_hosts}. New: {summary.new_devices}. "
        f"IP changes: {summary.changed_ip_devices}. Offline tracked: {summary.offline_devices}."
    )
    if Console:
        Console().print(f"[bold cyan]{text}[/bold cyan]")
    else:
        print(text)


def print_history(rows: Iterable[Any]) -> None:
    rows = list(rows)
    if Console and Table:
        console = Console()
        table = Table(title="Recent sightings", box=box.SIMPLE_HEAVY)
        for column in ["Device", "Seen", "IP", "Name", "MAC", "Latency", "Source"]:
            table.add_column(column)
        for row in rows:
            table.add_row(
                str(row["device_id"]),
                row["seen_at"],
                row["ip"],
                row["hostname"] or "-",
                row["mac"] or "-",
                f"{row['latency_ms']:.1f} ms" if row["latency_ms"] is not None else "-",
                row["source"],
            )
        console.print(table)
        return

    print("Recent sightings")
    _print_rows_plain(
        ["device", "seen", "ip", "name", "mac", "latency", "source"],
        [
            [
                row["device_id"],
                row["seen_at"],
                row["ip"],
                row["hostname"] or "-",
                row["mac"] or "-",
                f"{row['latency_ms']:.1f} ms" if row["latency_ms"] is not None else "-",
                row["source"],
            ]
            for row in rows
        ],
    )


def export_devices(devices: list[TrackedDevice], path: Path, file_format: str) -> None:
    data = [device_to_dict(device) for device in devices]
    if file_format == "json":
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(data[0].keys()) if data else ["id"])
        writer.writeheader()
        writer.writerows(data)


def device_to_dict(device: TrackedDevice) -> dict[str, Any]:
    data = asdict(device)
    data["id"] = data.pop("device_id")
    data["first_seen"] = format_time(device.first_seen)
    data["last_seen"] = format_time(device.last_seen)
    return data


def _print_devices_rich(devices: list[TrackedDevice], title: str) -> None:
    console = Console()
    table = Table(title=title, box=box.SIMPLE_HEAVY, show_lines=False)
    for column in ["ID", "Status", "IP", "Prev IP", "Name", "MAC", "Vendor", "Seen", "Moves", "Last Seen"]:
        justify = "right" if column in {"ID", "Seen", "Moves"} else "left"
        table.add_column(column, justify=justify, no_wrap=column in {"ID", "Status", "IP", "Prev IP", "MAC"})
    for device in devices:
        status = "[green]online[/green]" if device.last_status == "online" else "[red]offline[/red]"
        table.add_row(
            str(device.device_id),
            status,
            device.current_ip,
            device.previous_ip or "-",
            device.hostname or "-",
            device.mac or "-",
            device.vendor or "-",
            str(device.seen_count),
            str(device.ip_changes),
            format_time(device.last_seen),
        )
    console.print(table)


def _print_devices_plain(devices: list[TrackedDevice], title: str) -> None:
    print(title)
    _print_rows_plain(
        ["id", "status", "ip", "prev ip", "name", "mac", "vendor", "seen", "moves", "last seen"],
        [
            [
                device.device_id,
                device.last_status,
                device.current_ip,
                device.previous_ip or "-",
                device.hostname or "-",
                device.mac or "-",
                device.vendor or "-",
                device.seen_count,
                device.ip_changes,
                format_time(device.last_seen),
            ]
            for device in devices
        ],
    )


def _print_rows_plain(headers: list[str], rows: list[list[Any]]) -> None:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(str(value)))
    line = "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))
    print(line)
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(str(value).ljust(widths[index]) for index, value in enumerate(row)))
    if not rows:
        print("(no rows)")


def stderr(message: str) -> None:
    print(message, file=sys.stderr)
