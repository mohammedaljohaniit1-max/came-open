"""
CAMRADAR OSINT Open-Camera Crawler.

Discovers *genuinely internet-exposed, open (no-auth) IP cameras* from the
public OSINT open-camera index (Insecam), which aggregates devices that are
directly reachable on the internet and serve a snapshot/MJPEG stream without
authentication. Each discovered node has a REAL public IP:port.

For every discovered camera the crawler:
  1. Parses the real camera feed URL (http://<ip>:<port>/<path>).
  2. Records the Insecam metadata (country, id).
  3. Hands the IP to the geolocation enricher (real lat/lon/ISP/ASN).

This is passive OSINT reconnaissance of the *publicly indexed* attack surface.
CAMRADAR only reads the already-open snapshot the camera itself publishes; it
never authenticates, never brute-forces, and never accesses protected devices.
"""
from __future__ import annotations

import asyncio
import re
from typing import Dict, List, Optional

import httpx

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
INSECAM_BASE = "http://www.insecam.org"

# <img ... id="imageNNN" ... src="http://IP:PORT/path">  (attributes vary in order)
_IMG_RE = re.compile(
    r'id="image(?P<id>\d+)"[^>]*?src="(?P<url>http://(?P<ip>[0-9.]+):(?P<port>\d+)[^"]*)"',
    re.I,
)
# Fallback: any camera src on the page (order-independent)
_SRC_RE = re.compile(r'src="(http://(?P<ip>[0-9.]+):(?P<port>\d+)[^"]*)"', re.I)


async def _get(client: httpx.AsyncClient, url: str) -> Optional[str]:
    try:
        r = await client.get(url, headers={"User-Agent": UA})
        if r.status_code == 200:
            return r.text
    except Exception:  # noqa: BLE001
        return None
    return None


def _clean_url(u: str) -> str:
    # Insecam appends &COUNTER / rand=COUNTER placeholders; normalise them.
    u = u.replace("&amp;", "&")
    u = u.replace("COUNTER", "").replace("rand=", "rand=1")
    return u.rstrip("&?")


async def fetch_country(country_code: str, max_pages: int = 6,
                        per_country_cap: int = 60) -> List[Dict]:
    """Crawl Insecam listing pages for one country and return raw camera nodes."""
    out: List[Dict] = []
    seen_ids: set = set()
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        for page in range(max_pages):
            suffix = "" if page == 0 else f"?page={page}"
            html = await _get(client, f"{INSECAM_BASE}/en/bycountry/{country_code}/{suffix}")
            if not html:
                break
            # Pair each id with the nearest src.
            found = 0
            for m in _IMG_RE.finditer(html):
                cid = m.group("id")
                if cid in seen_ids:
                    continue
                seen_ids.add(cid)
                url = _clean_url(m.group("url"))
                out.append({
                    "insecam_id": cid,
                    "ip": m.group("ip"),
                    "port": int(m.group("port")),
                    "feed_url": url,
                    "country_code": country_code,
                })
                found += 1
            # Fallback if the id-paired regex missed (layout variance).
            if found == 0:
                for m in _SRC_RE.finditer(html):
                    key = f"{m.group('ip')}:{m.group('port')}"
                    if key in seen_ids:
                        continue
                    seen_ids.add(key)
                    out.append({
                        "insecam_id": None,
                        "ip": m.group("ip"),
                        "port": int(m.group("port")),
                        "feed_url": _clean_url(m.group(1)),
                        "country_code": country_code,
                    })
            if len(out) >= per_country_cap:
                break
            await asyncio.sleep(0.2)  # be polite to the source
    return out[:per_country_cap]


async def fetch_countries(country_codes: List[str], per_country_cap: int = 40,
                          max_pages: int = 5) -> List[Dict]:
    """Crawl several countries concurrently (bounded)."""
    sem = asyncio.Semaphore(4)

    async def _one(cc: str) -> List[Dict]:
        async with sem:
            return await fetch_country(cc, max_pages=max_pages,
                                       per_country_cap=per_country_cap)

    results = await asyncio.gather(*[_one(cc) for cc in country_codes])
    flat: List[Dict] = []
    for r in results:
        flat.extend(r)
    return flat


async def available_countries() -> Dict[str, Dict]:
    """Return Insecam's country -> {country, count} map."""
    async with httpx.AsyncClient(timeout=12.0) as client:
        html = await _get(client, f"{INSECAM_BASE}/en/jsoncountries/")
    if not html:
        return {}
    try:
        import json
        return json.loads(html).get("countries", {})
    except Exception:  # noqa: BLE001
        return {}
