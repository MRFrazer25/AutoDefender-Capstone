"""Offline GeoIP enrichment using local MaxMind GeoLite2 databases.

Lookups happen entirely on this machine, so attacker IPs are never sent to
a third party. Download the free GeoLite2-City and GeoLite2-ASN databases
(https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) and point
these environment variables at the .mmdb files:

    AUTODEFENDER_GEOIP_CITY_DB=/path/to/GeoLite2-City.mmdb
    AUTODEFENDER_GEOIP_ASN_DB=/path/to/GeoLite2-ASN.mmdb   (optional)

Without them, enrichment is simply skipped.
"""

import ipaddress
import logging
import os
import re
import threading
from functools import lru_cache
from typing import Dict, Optional

logger = logging.getLogger(__name__)

CITY_DB_ENV = "AUTODEFENDER_GEOIP_CITY_DB"
ASN_DB_ENV = "AUTODEFENDER_GEOIP_ASN_DB"

# Longest value kept from any GeoIP field
MAX_FIELD_LENGTH = 100

_readers: Dict[str, object] = {}
_readers_lock = threading.Lock()


def _reader(env_name: str):
    """Return a cached geoip2 Reader for the database named by env_name, or None."""
    path = os.getenv(env_name, "").strip()
    if not path or not os.path.isfile(path):
        return None
    with _readers_lock:
        if path not in _readers:
            try:
                import geoip2.database  # Optional dependency
                _readers[path] = geoip2.database.Reader(path)
                logger.info(f"Loaded GeoIP database {os.path.basename(path)}")
            except Exception as e:
                logger.warning(f"Could not open GeoIP database {path}: {e}")
                _readers[path] = None
        return _readers[path]


def geoip_enabled() -> bool:
    """Return True if a GeoLite2 City database is configured."""
    return _reader(CITY_DB_ENV) is not None


def is_public_ip(ip: str) -> bool:
    """Check if an IP address is public (routable)."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _clean_field(value) -> str:
    """Keep GeoIP values short, single-line, and free of markup characters."""
    text = re.sub(r"[\x00-\x1f\x7f<>\[\]`*_\"\\;]", " ", str(value or ""))
    return " ".join(text.split())[:MAX_FIELD_LENGTH]


@lru_cache(maxsize=4096)
def get_ip_context(ip: str) -> Optional[Dict[str, str]]:
    """
    Look up geographic and network context for a public IP in the local databases.

    Returns enrichment data, or None if the IP is private, unknown, or no database is configured.
    """
    city_reader = _reader(CITY_DB_ENV)
    if city_reader is None or not is_public_ip(ip):
        return None

    try:
        city = city_reader.city(ip)
    except Exception:
        # AddressNotFoundError and friends: no data for this IP
        return None

    context = {
        "country": _clean_field(city.country.name or "Unknown"),
        "country_code": _clean_field(city.country.iso_code or ""),
        "region": _clean_field(city.subdivisions.most_specific.name or ""),
        "city": _clean_field(city.city.name or ""),
        "isp": "Unknown",
        "org": "",
        "as_number": "",
    }

    asn_reader = _reader(ASN_DB_ENV)
    if asn_reader is not None:
        try:
            asn = asn_reader.asn(ip)
            context["isp"] = _clean_field(asn.autonomous_system_organization or "Unknown")
            if asn.autonomous_system_number:
                context["as_number"] = f"AS{asn.autonomous_system_number}"
        except Exception:
            pass

    # Build a human-readable location string
    location_parts = [context["city"], context["region"], context["country"]]
    context["location"] = ", ".join(p for p in location_parts if p)
    return context


def enrich_threat_context(threat_data: Dict) -> Dict:
    """
    Add geographic context to threat data if source IP is available.

    Modifies threat_data in place by adding 'geo_context' field.
    """
    src_ip = threat_data.get("source_ip")
    if not src_ip:
        return threat_data

    context = get_ip_context(src_ip)
    if context:
        threat_data["geo_context"] = context
        logger.debug(f"Enriched {src_ip} with context: {context.get('location', 'Unknown')}")

    return threat_data
