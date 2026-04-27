# network_scanner

A polished Python CLI for scanning your local network and tracking devices as
they move between IP addresses.

It is designed for the common home/lab problem where machines reboot, renew DHCP
leases, and come back with a different address. The scanner records each
sighting in SQLite and uses the best available fingerprint, preferring MAC
address, then hostname, then IP address.

## Features

- Auto-detects the local IPv4 network or accepts an explicit CIDR.
- Concurrent ping sweep with ARP/MAC enrichment.
- Reverse DNS hostname lookup.
- Persistent SQLite inventory and sighting history.
- Detects IP changes for known devices.
- Marks devices offline when they have not been seen recently.
- Clean table output, with richer styling when `rich` is installed.
- CSV and JSON export.

## Install

Run directly from the repository:

```powershell
python -m network_scanner --help
```

Optional fancy table output:

```powershell
python -m pip install -e ".[fancy]"
netscan --help
```

## Quick Start

Show detected local networks:

```powershell
python -m network_scanner networks
```

Scan the detected network:

```powershell
python -m network_scanner scan
```

Scan a specific range:

```powershell
python -m network_scanner scan 192.168.1.0/24
```

Watch continuously every 60 seconds:

```powershell
python -m network_scanner watch --interval 60
```

Show tracked devices without scanning:

```powershell
python -m network_scanner devices
```

Show recent sightings:

```powershell
python -m network_scanner history --limit 50
```

Export the inventory:

```powershell
python -m network_scanner export devices.csv
python -m network_scanner export devices.json --format json
```

## Notes

This scanner intentionally avoids raw sockets and packet capture drivers, so it
does not require administrator privileges. It relies on normal OS tools such as
`ping`, `arp`, and `ipconfig` where available.

The default database is stored at:

```text
~/.network-scanner/devices.sqlite3
```

Use `--db` if you want to keep a project-local or portable database:

```powershell
python -m network_scanner --db .\devices.sqlite3 scan 192.168.1.0/24
```
