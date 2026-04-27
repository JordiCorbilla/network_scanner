from datetime import timedelta

from network_scanner.models import SeenDevice, utc_now
from network_scanner.store import DeviceStore


def test_record_scan_tracks_ip_changes_by_mac(tmp_path):
    store = DeviceStore(tmp_path / "devices.sqlite3")
    try:
        started = utc_now()
        first = [SeenDevice(ip="192.168.1.10", hostname="box", mac="00:11:22:33:44:55")]
        store.record_scan(cidr="192.168.1.0/24", scanned_hosts=254, seen_devices=first, started_at=started)

        second = [SeenDevice(ip="192.168.1.44", hostname="box", mac="00:11:22:33:44:55")]
        store.record_scan(
            cidr="192.168.1.0/24",
            scanned_hosts=254,
            seen_devices=second,
            started_at=started + timedelta(minutes=1),
        )

        devices = store.devices()
        assert len(devices) == 1
        assert devices[0].current_ip == "192.168.1.44"
        assert devices[0].previous_ip == "192.168.1.10"
        assert devices[0].ip_changes == 1
        assert devices[0].seen_count == 2
    finally:
        store.close()
