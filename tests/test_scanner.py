from network_scanner.scanner import normalize_mac, parse_arp_table


def test_normalize_mac_accepts_common_formats():
    assert normalize_mac("00-0c-29-aa-bb-cc") == "00:0C:29:AA:BB:CC"
    assert normalize_mac("00:0c:29:aa:bb:cc") == "00:0C:29:AA:BB:CC"


def test_parse_windows_arp_table():
    output = """
Interface: 192.168.1.10 --- 0x12
  Internet Address      Physical Address      Type
  192.168.1.1           00-11-22-33-44-55     dynamic
  192.168.1.99          aa-bb-cc-dd-ee-ff     dynamic
"""
    assert parse_arp_table(output) == {
        "192.168.1.1": "00:11:22:33:44:55",
        "192.168.1.99": "AA:BB:CC:DD:EE:FF",
    }
