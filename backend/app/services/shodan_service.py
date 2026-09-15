"""
Shodan enrichment service.

CRITICAL SCOPE: The provided key runs on the OSS plan with 0 query credits.
Only these credit-free endpoints are used:
  - GET /shodan/host/{ip}      -> single-host enrichment (ISP, ASN, org, vulns...)
  - GET /shodan/host/count     -> facet statistics / distribution counts

The paid bulk endpoint /shodan/host/search (which returns 403 on this plan) is
NEVER called. On any error we return a structured error object rather than
fabricating data.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Dict, Optional

import httpx

from ..core.config import settings

_cache: Dict[str, Dict] = {}
_cache_lock = asyncio.Lock()


async def _resolve(host: str) -> Optional[str]:
    """Resolve a hostname to an IPv4 address (Shodan /host/{ip} needs an IP)."""
    # Strip any accidental scheme/port.
    host = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    try:
        ipaddress.ip_address(host)
        return host  # already an IP
    except ValueError:
        pass
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, socket.gethostbyname, host)
    except Exception:  # noqa: BLE001
        return None


async def enrich_host(host: str, use_cache: bool = True) -> Dict:
    """Fetch single-host metadata from the credit-free /shodan/host/{ip}.

    Accepts either an IP or a hostname (resolved to IPv4 first).
    """
    if use_cache and host in _cache:
        return _cache[host]

    ip = await _resolve(host)
    if not ip:
        return {"ip": host, "error": "Could not resolve host to an IP address."}

    url = f"{settings.SHODAN_BASE_URL}/shodan/host/{ip}"
    params = {"key": settings.SHODAN_API_KEY}
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(url, params=params)
        if resp.status_code == 200:
            data = resp.json()
            enriched = {
                "ip": ip,
                "org": data.get("org"),
                "isp": data.get("isp"),
                "asn": data.get("asn"),
                "country_name": data.get("country_name"),
                "city": data.get("city"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "os": data.get("os"),
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "vulns": data.get("vulns", []) if isinstance(data.get("vulns"), list)
                else list(data.get("vulns", {})),
                "tags": data.get("tags", []),
                "last_update": data.get("last_update"),
                "error": None,
            }
            enriched["resolved_ip"] = ip
            async with _cache_lock:
                _cache[host] = enriched
                _cache[ip] = enriched
            return enriched
        if resp.status_code == 404:
            return {"ip": ip, "resolved_ip": ip,
                    "error": f"No Shodan record indexed for {ip} (404)."}
        if resp.status_code in (401, 403):
            return {"ip": ip, "resolved_ip": ip,
                    "error": f"Host {ip} not accessible on Shodan OSS plan ({resp.status_code})."}
        return {"ip": ip, "resolved_ip": ip, "error": f"Shodan HTTP {resp.status_code}"}
    except Exception as exc:  # noqa: BLE001
        return {"ip": ip, "error": f"Shodan request failed: {type(exc).__name__}"}


async def host_count(query: str, facets: Optional[str] = None) -> Dict:
    """
    Call the credit-free /shodan/host/count endpoint for distribution stats.
    Returns total match count and requested facet breakdowns.
    """
    url = f"{settings.SHODAN_BASE_URL}/shodan/host/count"
    params = {"key": settings.SHODAN_API_KEY, "query": query}
    if facets:
        params["facets"] = facets
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(url, params=params)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "query": query,
                "total": data.get("total", 0),
                "facets": data.get("facets", {}),
                "error": None,
            }
        return {"query": query, "total": 0, "facets": {},
                "error": f"Shodan count HTTP {resp.status_code}"}
    except Exception as exc:  # noqa: BLE001
        return {"query": query, "total": 0, "facets": {},
                "error": f"Shodan count failed: {type(exc).__name__}"}
