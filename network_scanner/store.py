from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from .models import ScanSummary, SeenDevice, TrackedDevice, format_time, parse_time, utc_now


APP_DIR_NAME = ".network-scanner"
DB_NAME = "devices.sqlite3"


@dataclass(frozen=True)
class ScanResult:
    summary: ScanSummary
    devices: list[TrackedDevice]


def default_db_path() -> Path:
    return Path.home() / APP_DIR_NAME / DB_NAME


class DeviceStore:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.migrate()

    def close(self) -> None:
        self.connection.close()

    def migrate(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL UNIQUE,
                hostname TEXT,
                mac TEXT,
                vendor TEXT,
                current_ip TEXT NOT NULL,
                previous_ip TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 0,
                ip_changes INTEGER NOT NULL DEFAULT 0,
                last_latency_ms REAL,
                last_status TEXT NOT NULL DEFAULT 'online'
            );

            CREATE TABLE IF NOT EXISTS sightings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                seen_at TEXT NOT NULL,
                ip TEXT NOT NULL,
                hostname TEXT,
                mac TEXT,
                latency_ms REAL,
                source TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                cidr TEXT NOT NULL,
                scanned_hosts INTEGER NOT NULL,
                alive_hosts INTEGER NOT NULL,
                new_devices INTEGER NOT NULL,
                changed_ip_devices INTEGER NOT NULL,
                offline_devices INTEGER NOT NULL
            );
            """
        )
        self.connection.commit()

    def record_scan(
        self,
        *,
        cidr: str,
        scanned_hosts: int,
        seen_devices: list[SeenDevice],
        started_at: datetime,
        finished_at: datetime | None = None,
        offline_after_minutes: int = 10,
    ) -> ScanResult:
        finished = finished_at or utc_now()
        now_text = format_time(finished)
        new_devices = 0
        changed_ip_devices = 0
        tracked: list[TrackedDevice] = []

        with self.connection:
            for seen in seen_devices:
                fingerprint = fingerprint_for(seen)
                row = self._find_device(fingerprint, seen)
                if row is None:
                    new_devices += 1
                    cursor = self.connection.execute(
                        """
                        INSERT INTO devices (
                            fingerprint, hostname, mac, vendor, current_ip, first_seen,
                            last_seen, seen_count, last_latency_ms, last_status
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 'online')
                        """,
                        (
                            fingerprint,
                            seen.hostname,
                            seen.mac,
                            seen.vendor,
                            seen.ip,
                            now_text,
                            now_text,
                            seen.latency_ms,
                        ),
                    )
                    device_id = int(cursor.lastrowid)
                    previous_ip = None
                else:
                    device_id = int(row["id"])
                    previous_ip = row["current_ip"] if row["current_ip"] != seen.ip else row["previous_ip"]
                    if row["current_ip"] != seen.ip:
                        changed_ip_devices += 1
                    self.connection.execute(
                        """
                        UPDATE devices
                        SET hostname = COALESCE(?, hostname),
                            mac = COALESCE(?, mac),
                            vendor = COALESCE(?, vendor),
                            previous_ip = CASE WHEN current_ip != ? THEN current_ip ELSE previous_ip END,
                            current_ip = ?,
                            last_seen = ?,
                            seen_count = seen_count + 1,
                            ip_changes = ip_changes + CASE WHEN current_ip != ? THEN 1 ELSE 0 END,
                            last_latency_ms = ?,
                            last_status = 'online'
                        WHERE id = ?
                        """,
                        (
                            seen.hostname,
                            seen.mac,
                            seen.vendor,
                            seen.ip,
                            seen.ip,
                            now_text,
                            seen.ip,
                            seen.latency_ms,
                            device_id,
                        ),
                    )
                self.connection.execute(
                    """
                    INSERT INTO sightings (device_id, seen_at, ip, hostname, mac, latency_ms, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (device_id, now_text, seen.ip, seen.hostname, seen.mac, seen.latency_ms, seen.source),
                )

            cutoff = finished - timedelta(minutes=offline_after_minutes)
            self.connection.execute(
                """
                UPDATE devices
                SET last_status = 'offline'
                WHERE last_seen < ? AND last_status = 'online'
                """,
                (format_time(cutoff),),
            )
            offline_devices = int(
                self.connection.execute("SELECT COUNT(*) FROM devices WHERE last_status = 'offline'").fetchone()[0]
            )
            summary = ScanSummary(
                started_at=started_at,
                finished_at=finished,
                cidr=cidr,
                scanned_hosts=scanned_hosts,
                alive_hosts=len(seen_devices),
                new_devices=new_devices,
                changed_ip_devices=changed_ip_devices,
                offline_devices=offline_devices,
            )
            self.connection.execute(
                """
                INSERT INTO scans (
                    started_at, finished_at, cidr, scanned_hosts, alive_hosts,
                    new_devices, changed_ip_devices, offline_devices
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    format_time(summary.started_at),
                    format_time(summary.finished_at),
                    summary.cidr,
                    summary.scanned_hosts,
                    summary.alive_hosts,
                    summary.new_devices,
                    summary.changed_ip_devices,
                    summary.offline_devices,
                ),
            )

            for seen in seen_devices:
                row = self._find_device(fingerprint_for(seen), seen)
                if row:
                    tracked.append(row_to_device(row))

        return ScanResult(summary=summary, devices=tracked)

    def devices(self, status: str = "all") -> list[TrackedDevice]:
        query = "SELECT * FROM devices"
        params: tuple[str, ...] = ()
        if status != "all":
            query += " WHERE last_status = ?"
            params = (status,)
        query += " ORDER BY last_status DESC, current_ip"
        return [row_to_device(row) for row in self.connection.execute(query, params)]

    def history(self, limit: int = 20) -> list[sqlite3.Row]:
        return list(
            self.connection.execute(
                """
                SELECT d.id AS device_id, s.seen_at, s.ip, s.hostname, s.mac, s.latency_ms, s.source
                FROM sightings s
                JOIN devices d ON d.id = s.device_id
                ORDER BY s.seen_at DESC, s.id DESC
                LIMIT ?
                """,
                (limit,),
            )
        )

    def forget(self, device_id: int) -> bool:
        with self.connection:
            cursor = self.connection.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        return cursor.rowcount > 0

    def _find_device(self, fingerprint: str, seen: SeenDevice) -> sqlite3.Row | None:
        row = self.connection.execute("SELECT * FROM devices WHERE fingerprint = ?", (fingerprint,)).fetchone()
        if row:
            return row
        if seen.mac:
            row = self.connection.execute("SELECT * FROM devices WHERE mac = ?", (seen.mac,)).fetchone()
            if row:
                return row
        return None


def fingerprint_for(device: SeenDevice) -> str:
    if device.mac:
        return f"mac:{device.mac}"
    if device.hostname:
        return f"host:{device.hostname.lower()}"
    return f"ip:{device.ip}"


def row_to_device(row: sqlite3.Row) -> TrackedDevice:
    return TrackedDevice(
        device_id=int(row["id"]),
        fingerprint=row["fingerprint"],
        hostname=row["hostname"],
        mac=row["mac"],
        vendor=row["vendor"],
        current_ip=row["current_ip"],
        previous_ip=row["previous_ip"],
        first_seen=parse_time(row["first_seen"]) or utc_now(),
        last_seen=parse_time(row["last_seen"]) or utc_now(),
        seen_count=int(row["seen_count"]),
        ip_changes=int(row["ip_changes"]),
        last_latency_ms=row["last_latency_ms"],
        last_status=row["last_status"],
    )
