"""GeoIP and IP reputation enrichment utilities."""

import logging
import ipaddress
import httpx
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Free GeoIP service (no API key required)
GEOIP_API = "http://ip-api.com/json/{ip}"

# Rate limit: 45 requests per minute for free tier
REQUEST_TIMEOUT = 5


def is_public_ip(ip: str) -> bool:
    """Check if an IP address is public (routable)."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )
    except ValueError:
        return False


def get_ip_context(ip: str) -> Optional[Dict[str, str]]:
    """
    Fetch geographic and network context for an IP address.
    
    Returns enrichment data or None if lookup fails or IP is private.
    """
    if not is_public_ip(ip):
        return None
    
    try:
        url = GEOIP_API.format(ip=ip)
        response = httpx.get(url, timeout=REQUEST_TIMEOUT)
        
        if response.status_code != 200:
            logger.warning(f"GeoIP lookup failed for {ip}: HTTP {response.status_code}")
            return None
        
        data = response.json()
        
        if data.get("status") == "fail":
            logger.warning(f"GeoIP lookup failed for {ip}: {data.get('message', 'Unknown error')}")
            return None
        
        # Extract relevant fields
        context = {
            "country": data.get("country", "Unknown"),
            "country_code": data.get("countryCode", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "isp": data.get("isp", "Unknown"),
            "org": data.get("org", ""),
            "as_number": data.get("as", ""),
        }
        
        # Build a human-readable location string
        location_parts = [context["city"], context["region"], context["country"]]
        context["location"] = ", ".join(p for p in location_parts if p)
        
        return context
    
    except httpx.TimeoutException:
        logger.warning(f"GeoIP lookup timed out for {ip}")
        return None
    except Exception as e:
        logger.error(f"GeoIP lookup error for {ip}: {e}")
        return None


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
        logger.info(f"Enriched {src_ip} with context: {context.get('location', 'Unknown')}")
    
    return threat_data

