from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


UTC = timezone.utc


def utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def format_time(value: datetime | None) -> str:
    if value is None:
        return "-"
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class ScanTarget:
    ip: str


@dataclass(frozen=True)
class SeenDevice:
    ip: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    latency_ms: float | None = None
    source: str = "scan"


@dataclass(frozen=True)
class TrackedDevice:
    device_id: int
    fingerprint: str
    current_ip: str
    first_seen: datetime
    last_seen: datetime
    last_status: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    previous_ip: str | None = None
    seen_count: int = 0
    ip_changes: int = 0
    last_latency_ms: float | None = None


@dataclass(frozen=True)
class ScanSummary:
    started_at: datetime
    finished_at: datetime
    cidr: str
    scanned_hosts: int
    alive_hosts: int
    new_devices: int
    changed_ip_devices: int
    offline_devices: int
