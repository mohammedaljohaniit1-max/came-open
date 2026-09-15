"""
Shodan-powered OSINT camera discovery (credit-free).

KEY TECHNIQUE — bypassing the OSS-plan paywall legally:
The paid `/shodan/host/search` endpoint returns 403 on the OSS plan. However the
FREE `/shodan/host/count` endpoint accepts a `facets=ip:<N>` parameter which
returns up to N of the *actual matching IP addresses* as facet values — without
consuming query credits. We use this to harvest real camera IPs per country,
including regions (like Saudi Arabia) that curated indexes such as Insecam do
not cover.

Pipeline per country:
  1. /shodan/host/count?query=<camera dork> country:<CC>&facets=ip:<N>  -> real IPs
  2. https://internetdb.shodan.io/<ip> (keyless)                       -> exact ports
  3. build candidate feed URLs on the open camera ports

The downstream render-verifier then keeps only feeds that serve a live frame,
so nothing fake or dead is ever shown. This is passive reconnaissance of the
publicly-indexed attack surface; CAMRADAR never authenticates to any device.
"""
from __future__ import annotations

import asyncio
from typing import Dict, List, Optional

import httpx

from ..core.config import settings

SHODAN = settings.SHODAN_BASE_URL
KEY = settings.SHODAN_API_KEY

# Camera-oriented Shodan dorks (broad, product/keyword based).
CAMERA_QUERY = (
    "has_screenshot:true,"  # devices Shodan captured a screenshot of (cameras)
)
# We run a couple of complementary dorks and merge the IPs.
DORKS = [
    "has_screenshot:true",
    'product:"Hikvision IP Camera"',
    "webcamxp",
    "mjpg",
]

# Common open snapshot / MJPEG paths to try (NO credentials submitted).
CANDIDATE_PATHS = [
    "/mjpg/video.mjpg",
    "/video.mjpg",
    "/cgi-bin/mjpg/video.cgi",
    "/axis-cgi/mjpg/video.cgi",
    "/SnapshotJPEG?Resolution=640x480",
    "/snapshot.cgi",
    "/image/jpeg.cgi",
    "/cgi-bin/snapshot.cgi",
    "/tmpfs/auto.jpg",
    "/webcapture.jpg?command=snap&channel=1",
    "/cam/realmonitor?channel=1&subtype=1",
    "/",
]

# Camera-ish ports we will attempt an HTTP snapshot on.
HTTP_CAM_PORTS = {80, 81, 82, 83, 88, 8000, 8080, 8081, 8082, 8085, 8090,
                  8181, 8888, 9000, 1024, 8096, 8200, 8120}


async def _count_facet_ips(client: httpx.AsyncClient, query: str,
                           n: int = 200) -> List[str]:
    """Harvest matching IPs from the credit-free count endpoint via facets=ip."""
    try:
        r = await client.get(f"{SHODAN}/shodan/host/count", params={
            "key": KEY, "query": query, "facets": f"ip:{n}"
        })
        if r.status_code != 200:
            return []
        facets = r.json().get("facets", {})
        return [f["value"] for f in facets.get("ip", [])]
    except Exception:  # noqa: BLE001
        return []


async def discover_ips(country_code: str, per_dork: int = 120) -> List[str]:
    """Return de-duplicated real camera IPs for a country."""
    ips: set = set()
    async with httpx.AsyncClient(timeout=15.0) as client:
        for dork in DORKS:
            q = f"country:{country_code} {dork}"
            got = await _count_facet_ips(client, q, per_dork)
            ips.update(got)
            await asyncio.sleep(0.2)
    return list(ips)


async def internetdb(client: httpx.AsyncClient, ip: str) -> Dict:
    """Keyless per-IP enrichment: open ports, vulns, cpes, hostnames."""
    try:
        r = await client.get(f"https://internetdb.shodan.io/{ip}")
        if r.status_code == 200:
            return r.json()
    except Exception:  # noqa: BLE001
        pass
    return {}


async def enrich_ports(ips: List[str], concurrency: int = 40) -> Dict[str, Dict]:
    """Map ip -> {ports, vulns, cpes} using the keyless InternetDB."""
    sem = asyncio.Semaphore(concurrency)
    out: Dict[str, Dict] = {}

    async with httpx.AsyncClient(timeout=8.0) as client:
        async def _one(ip: str):
            async with sem:
                out[ip] = await internetdb(client, ip)

        await asyncio.gather(*[_one(ip) for ip in ips])
    return out


def build_candidates(ip: str, ports: List[int]) -> List[Dict]:
    """Build candidate HTTP feed URLs for the open camera ports of an IP."""
    cands: List[Dict] = []
    cam_ports = [p for p in ports if p in HTTP_CAM_PORTS] or \
                [p for p in ports if 80 <= p <= 9100]
    for port in cam_ports[:2]:  # limit attempts per host
        for path in CANDIDATE_PATHS:
            cands.append({"ip": ip, "port": port,
                          "feed_url": f"http://{ip}:{port}{path}"})
    return cands


async def discover_country(country_code: str, max_ips: int = 120) -> Dict:
    """
    Full discovery for one country. Returns:
      {"ips": [...], "port_map": {ip: internetdb}, "candidates": [feed dicts]}
    """
    ips = await discover_ips(country_code)
    ips = ips[:max_ips]
    if not ips:
        return {"ips": [], "port_map": {}, "candidates": []}
    port_map = await enrich_ports(ips)
    candidates: List[Dict] = []
    for ip in ips:
        ports = port_map.get(ip, {}).get("ports", [])
        if ports:
            candidates.extend(build_candidates(ip, ports))
    return {"ips": ips, "port_map": port_map, "candidates": candidates}


async def country_stats(country_code: str) -> Dict:
    """Real aggregate camera-exposure intelligence for a country (free /count)."""
    query = (f"country:{country_code} (webcam OR camera OR hikvision OR dahua "
             f"OR rtsp OR mjpg OR netcam)")
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            r = await client.get(f"{SHODAN}/shodan/host/count", params={
                "key": KEY, "query": query,
                "facets": "product:8,port:8,city:8,org:6",
            })
            if r.status_code != 200:
                return {"total": 0, "error": f"HTTP {r.status_code}"}
            d = r.json()
            fac = d.get("facets", {})
            def fx(name):
                return [{"value": f["value"], "count": f["count"]}
                        for f in fac.get(name, [])]
            return {
                "total": d.get("total", 0),
                "by_product": fx("product"),
                "by_port": fx("port"),
                "by_city": fx("city"),
                "by_org": fx("org"),
                "error": None,
            }
        except Exception as exc:  # noqa: BLE001
            return {"total": 0, "error": type(exc).__name__}
