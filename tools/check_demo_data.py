#!/usr/bin/env python3
"""Fail if repository files contain real-world IP addresses or organization names.

Demo data, docs, and examples must only use private ranges (RFC 1918),
documentation ranges (RFC 5737 / RFC 3849), and fictional "Example ..."
organizations, so the project never attributes attacks to real hosts or
companies.

Usage: python tools/check_demo_data.py   (exit code 1 if anything is found)
"""

import ipaddress
import json
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Documentation-only ranges; is_global is False for private/loopback/etc. already
DOCUMENTATION_NETS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]

# Public addresses that appear only as well-known examples, never as attackers
ALLOWED_PUBLIC_IPS = set()

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6 = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])")

# GeoIP fields in demo data must name fictional organizations
GEO_NAME_FIELDS = ("isp", "org")

# AS numbers reserved for documentation (RFC 5398)
DOCUMENTATION_ASNS = set(range(64496, 64512)) | set(range(65536, 65552))
ASN = re.compile(r"(?<![A-Za-z])AS(\d{1,10})(?!\d)")

TEXT_SUFFIXES = {".py", ".md", ".json", ".txt", ".ini", ".toml", ".yaml", ".yml", ".rules", ".example"}
SQLITE_SUFFIXES = {".db", ".sqlite", ".sqlite3"}


def real_ips(text: str) -> set:
    """Return publicly routable IPs in text that are not documentation addresses."""
    found = set()
    for match in IPV4.findall(text) + IPV6.findall(text):
        try:
            addr = ipaddress.ip_address(match)
        except ValueError:
            continue
        if addr.is_global and not any(addr in net for net in DOCUMENTATION_NETS):
            if str(addr) not in ALLOWED_PUBLIC_IPS:
                found.add(str(addr))
    return found


def real_asns(text: str) -> set:
    """Return AS numbers in text that are not reserved for documentation."""
    return {f"AS{n}" for n in ASN.findall(text) if int(n) not in DOCUMENTATION_ASNS}


def check_geo(metadata_json: str) -> list:
    """Return GeoIP organization names that are not clearly fictional."""
    try:
        geo = (json.loads(metadata_json) or {}).get("geo_context") or {}
    except (json.JSONDecodeError, AttributeError):
        return []
    return [
        f"{field}={geo[field]!r}"
        for field in GEO_NAME_FIELDS
        if geo.get(field) and not str(geo[field]).startswith("Example") and geo[field] != "Unknown"
    ]


def tracked_files() -> list:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [ROOT / line for line in out.splitlines() if line]


def main() -> int:
    problems = []
    for path in tracked_files():
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if path.suffix in SQLITE_SUFFIXES:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                for table in ("threats", "actions"):
                    # Table names come from the fixed tuple above
                    for row in conn.execute(f"SELECT * FROM {table}"):  # nosec B608
                        text = " ".join(str(v) for v in row if v is not None)
                        for ip in real_ips(text):
                            problems.append(f"{rel} ({table} id {row[0]}): real IP {ip}")
                        for asn in real_asns(text):
                            problems.append(f"{rel} ({table} id {row[0]}): real AS number {asn}")
                for row_id, metadata in conn.execute("SELECT id, metadata FROM threats WHERE metadata IS NOT NULL"):
                    for name in check_geo(metadata):
                        problems.append(f"{rel} (threat id {row_id}): real-looking organization {name}")
            finally:
                conn.close()
        elif path.suffix in TEXT_SUFFIXES or path.name in {".gitignore"}:
            text = path.read_text(encoding="utf-8", errors="replace")
            for ip in real_ips(text):
                problems.append(f"{rel}: real IP {ip}")
            for asn in real_asns(text):
                problems.append(f"{rel}: real AS number {asn}")
            for match in re.finditer(r'"(?:isp|org)"\s*:\s*"([^"]+)"', text):
                if not match.group(1).startswith("Example") and match.group(1) != "Unknown":
                    problems.append(f"{rel}: real-looking organization {match.group(1)!r}")

    if problems:
        print("Real-world data found. Use 192.0.2.x / 198.51.100.x / 203.0.113.x, private ranges, "
              "and 'Example ...' organization names instead:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("OK: no real IP addresses or organization names in tracked files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
