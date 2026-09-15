"""
IP geolocation enrichment (ip-api.com free batch endpoint).

Resolves a real public IP to accurate country / city / lat-lon / ISP / ASN so
each discovered OSINT camera is placed correctly on the map. Batches up to 100
IPs per request; results cached in-process.
"""
from __future__ import annotations

import asyncio
from typing import Dict, List

import httpx

_BATCH_URL = ("http://ip-api.com/batch?fields=status,country,countryCode,"
              "city,lat,lon,isp,org,as,query")
_cache: Dict[str, Dict] = {}


async def geolocate(ips: List[str]) -> Dict[str, Dict]:
    """Return {ip: {country, countryCode, city, lat, lon, isp, org, asn}}."""
    result: Dict[str, Dict] = {}
    todo = []
    for ip in ips:
        if ip in _cache:
            result[ip] = _cache[ip]
        else:
            todo.append(ip)

    # ip-api free tier: 100 IPs / request, 45 requests / minute.
    async with httpx.AsyncClient(timeout=12.0) as client:
        for i in range(0, len(todo), 100):
            chunk = todo[i:i + 100]
            payload = [{"query": ip} for ip in chunk]
            try:
                r = await client.post(_BATCH_URL, json=payload)
                if r.status_code != 200:
                    continue
                for row in r.json():
                    if row.get("status") != "success":
                        continue
                    ip = row["query"]
                    geo = {
                        "country": row.get("country"),
                        "country_code": row.get("countryCode"),
                        "city": row.get("city"),
                        "lat": row.get("lat"),
                        "lon": row.get("lon"),
                        "isp": row.get("isp"),
                        "org": row.get("org") or row.get("isp"),
                        "asn": (row.get("as") or "").split(" ")[0] or None,
                    }
                    _cache[ip] = geo
                    result[ip] = geo
            except Exception:  # noqa: BLE001
                continue
            await asyncio.sleep(0.3)
    return result
