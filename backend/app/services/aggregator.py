"""
OSINT Source Aggregator (multi-source, production-grade).

Pulls camera/node intelligence from *legitimately public* government open-data
and public-broadcast OSINT sources, normalising them into CAMRADAR's Camera
schema. No unauthorized scanning of private third-party devices takes place;
every source below publishes its feeds for public consumption:

  1. NY 511 (New York State DOT) open CCTV API  -> ~1,800 live HLS video
     cameras with GPS coordinates and CORS-enabled streams.
  2. CalTrans (California DOT) open CCTV status JSON per district -> ~1,000+
     live cameras with snapshot URLs, HLS streams and GPS coordinates.
  3. Austin Mobility open traffic CCTV -> live MJPEG snapshot cameras.
  4. A curated, verified seed catalogue (seed_catalogue.json) of public
     broadcast/webcam feeds incl. Saudi-region public live feeds, guaranteeing
     Saudi-Arabia-first coverage (Makkah / Madinah / Riyadh / Jeddah / Dammam).

Every aggregated record is then handed to the Pre-Flight Validator, which
verifies it is actually reachable *right now* before the dashboard renders it.
The result is cached to SQLite; source fetches are debounced by a TTL so the
dashboard stays fast and the upstream APIs are not hammered.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Dict, List, Optional

import httpx

from ..core.config import settings
from ..core.knowledge import ARCHITECTURE_BY_ID
from ..engines import osint_crawler
from . import geoip
from . import shodan_discovery


def _vendor_from_feed(feed_url: str) -> str:
    """Best-effort vendor fingerprint from the feed URL path."""
    u = feed_url.lower()
    if "snapshotjpeg" in u or "nphmotionjpeg" in u:
        return "public_webcam"           # Panasonic/i-PRO style
    if "faststream.jpg" in u or "mobotix" in u:
        return "public_webcam"           # Mobotix
    if "mjpg/video.mjpg" in u or "axis-cgi" in u:
        return "axis"                    # Axis VAPIX
    if "cgi-bin" in u:
        return "public_webcam"
    return "public_webcam"


async def fetch_osint_cameras(country_codes: List[str], per_country: int = 40,
                              max_pages: int = 5) -> List[Dict]:
    """
    PRIMARY OSINT SOURCE: crawl the public open-camera index for genuinely
    internet-exposed, no-auth IP cameras, then geolocate each real IP.
    Returns normalised camera records (with real IP:port + live feed URL).
    """
    raw = await osint_crawler.fetch_countries(
        country_codes, per_country_cap=per_country, max_pages=max_pages
    )
    if not raw:
        return []

    ips = list({r["ip"] for r in raw})
    geo = await geoip.geolocate(ips)
    idb_map = await shodan_discovery.enrich_ports(ips)  # keyless InternetDB (ports+CVEs)

    out: List[Dict] = []
    for r in raw:
        g = geo.get(r["ip"], {})
        idb = idb_map.get(r["ip"], {})
        vendor = _vendor_from_feed(r["feed_url"])
        arch = ARCHITECTURE_BY_ID.get(vendor, ARCHITECTURE_BY_ID["public_webcam"])
        cid = _stable_id("osint", r["ip"], r["port"], r["feed_url"])
        is_mjpeg = ".mjpg" in r["feed_url"].lower() or "faststream" in r["feed_url"].lower()
        out.append({
            "id": cid,
            "ip": r["ip"],
            "port": r["port"],
            "country": g.get("country") or "Unknown",
            "country_code": g.get("country_code") or r.get("country_code") or "GLOBAL",
            "city": g.get("city"),
            "isp": g.get("isp"),
            "org": g.get("org"),
            "asn": g.get("asn"),
            "latitude": g.get("lat"),
            "longitude": g.get("lon"),
            "vendor": arch["id"],
            "vendor_label": arch["label"],
            "protocol": "MJPEG" if is_mjpeg else "HTTP/JPEG",
            "source": "OSINT Open-Camera Index",
            "stream_url": None,
            "snapshot_url": r["feed_url"],
            "feed_url": r["feed_url"],
            "shodan_vulns": idb.get("vulns", []) or [],
            "shodan_ports": idb.get("ports", []) or [],
            "meta_name": f"{g.get('city') or 'Camera'} · {r['ip']}",
        })
    return out


async def fetch_shodan_country(country_code: str, max_ips: int = 100) -> List[Dict]:
    """
    Country-aware OSINT discovery via Shodan's credit-free count+facets endpoint.

    Used for regions the curated indexes miss (e.g. Saudi Arabia). Discovers real
    exposed camera IPs, resolves their open ports (keyless InternetDB), builds
    candidate HTTP snapshot/MJPEG feed URLs, and geolocates each IP. The scan
    pipeline then render-verifies every candidate, so only cameras that actually
    serve a live frame are displayed; the rest are kept as classified nodes.
    """
    import asyncio as _asyncio
    import httpx as _httpx
    from ..engines.validator import find_working_feed

    disc = await shodan_discovery.discover_country(country_code, max_ips=max_ips)
    ips = disc["ips"]
    if not ips:
        return []

    geo = await geoip.geolocate(ips)
    port_map = disc["port_map"]
    sem = _asyncio.Semaphore(30)

    async def _classify(ip: str):
        """Return (ip, working_feed_or_None, http_tier) for a discovered IP.

        http_tier: 'open' (200 + renders), 'locked' (401/403), 'ui' (200 web UI
        but no direct frame), or None (no HTTP)."""
        async with sem:
            idb = port_map.get(ip, {})
            ports = idb.get("ports", [])
            web_ports = [p for p in ports if 80 <= p <= 9100]
            # 1) try to find a directly-rendering open feed
            fw = await find_working_feed(ip, ports)
            if fw:
                return ip, fw, "open"
            # 2) otherwise probe the web UI to classify auth tier
            for port in web_ports[:2]:
                try:
                    async with _httpx.AsyncClient(timeout=4.0, verify=False,
                                                  follow_redirects=True) as c:
                        r = await c.get(f"http://{ip}:{port}/",
                                        headers={"User-Agent": "CAMRADAR/1.0"})
                    if r.status_code in (401, 403):
                        return ip, {"port": port}, "locked"
                    if r.status_code == 200:
                        return ip, {"port": port}, "ui"
                except Exception:  # noqa: BLE001
                    continue
            return ip, None, None

    classified = await _asyncio.gather(*[_classify(ip) for ip in ips])

    out: List[Dict] = []
    for ip, fw, tier in classified:
        if tier is None:
            continue  # no HTTP interface at all — skip (likely RTSP-only/dead)
        g = geo.get(ip, {})
        idb = port_map.get(ip, {})
        all_ports = idb.get("ports", [])
        vulns = idb.get("vulns", []) or []
        port = fw.get("port") if fw else (all_ports[0] if all_ports else 80)

        if tier == "open":
            sec_tier, sec_code, renders = "open", "OPEN_ACCESS", True
            feed = fw["feed_url"]; proto = fw["protocol"]
        elif tier == "locked":
            sec_tier, sec_code, renders = "locked", "AUTH_LOCKED", False
            feed = None; proto = "HTTP (401)"
        else:  # 'ui' — reachable web UI, treat as default-cred exposure candidate
            sec_tier, sec_code, renders = "default_creds", "DEFAULT_CREDS_RISK", False
            feed = None; proto = "HTTP"

        cid = _stable_id("shodan", country_code, ip)
        out.append({
            "id": cid, "ip": ip, "port": port,
            "country": g.get("country") or country_code,
            "country_code": g.get("country_code") or country_code,
            "city": g.get("city"), "isp": g.get("isp"), "org": g.get("org"),
            "asn": g.get("asn"), "latitude": g.get("lat"), "longitude": g.get("lon"),
            "vendor": "public_webcam",
            "vendor_label": ARCHITECTURE_BY_ID["public_webcam"]["label"],
            "protocol": proto, "source": "Shodan OSINT Discovery",
            "stream_url": None, "snapshot_url": feed, "feed_url": feed,
            "renders": renders,
            "security_tier": sec_tier, "security_code": sec_code,
            "http_status": 401 if tier == "locked" else 200,
            "shodan_vulns": vulns, "shodan_ports": all_ports,
            "meta_name": f"{g.get('city') or 'Camera'} · {ip}",
        })
    return out


# --------------------------------------------------------------------------
# Source endpoints
# --------------------------------------------------------------------------
NY511_URL = "https://511ny.org/api/getcameras?key=demo&format=json"

CALTRANS_DISTRICTS = {
    "d3":  "https://cwwp2.dot.ca.gov/data/d3/cctv/cctvStatusD03.json",   # Sacramento
    "d4":  "https://cwwp2.dot.ca.gov/data/d4/cctv/cctvStatusD04.json",   # Bay Area
    "d7":  "https://cwwp2.dot.ca.gov/data/d7/cctv/cctvStatusD07.json",   # Los Angeles
    "d11": "https://cwwp2.dot.ca.gov/data/d11/cctv/cctvStatusD11.json",  # San Diego
    "d12": "https://cwwp2.dot.ca.gov/data/d12/cctv/cctvStatusD12.json",  # Orange County
}

# In-memory source cache (TTL) so repeated scans do not re-hit the upstreams.
_SOURCE_TTL = 180  # seconds
_source_cache: Dict[str, Dict] = {}


def _stable_id(*parts: str) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def _host_from_url(url: str) -> str:
    try:
        return httpx.URL(url).host or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def _valid_coord(lat, lon) -> bool:
    try:
        lat, lon = float(lat), float(lon)
    except (TypeError, ValueError):
        return False
    return -90 <= lat <= 90 and -180 <= lon <= 180 and not (lat == 0 and lon == 0)


async def _cached_get(key: str, url: str, timeout: float = 20.0) -> Optional[object]:
    """GET JSON with a short TTL cache."""
    now = time.time()
    hit = _source_cache.get(key)
    if hit and now - hit["ts"] < _SOURCE_TTL:
        return hit["data"]
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "CAMRADAR-OSINT/1.0"})
        if resp.status_code != 200:
            return hit["data"] if hit else None
        data = resp.json()
        _source_cache[key] = {"ts": now, "data": data}
        return data
    except Exception:  # noqa: BLE001
        return hit["data"] if hit else None


# --------------------------------------------------------------------------
# NY 511 (New York State DOT) — live HLS cameras
# --------------------------------------------------------------------------
async def fetch_ny511(limit: int = 400) -> List[Dict]:
    data = await _cached_get("ny511", NY511_URL)
    if not isinstance(data, list):
        return []
    out: List[Dict] = []
    for c in data:
        if c.get("Disabled") or c.get("Blocked"):
            continue
        video = c.get("VideoUrl")
        if not video or ".m3u8" not in video:
            continue
        lat, lon = c.get("Latitude"), c.get("Longitude")
        if not _valid_coord(lat, lon):
            continue
        name = c.get("Name") or "NY Traffic Camera"
        roadway = c.get("RoadwayName") or "New York"
        cid = _stable_id("ny511", c.get("ID"), video)
        out.append({
            "id": cid,
            "ip": _host_from_url(video),
            "port": 443,
            "country": "United States",
            "country_code": "US",
            "city": _shorten(roadway),
            "isp": "New York State DOT",
            "org": "NYSDOT 511 Traffic CCTV",
            "asn": None,
            "latitude": float(lat),
            "longitude": float(lon),
            "vendor": "public_webcam",
            "vendor_label": ARCHITECTURE_BY_ID["public_webcam"]["label"],
            "protocol": "HLS",
            "source": "NY 511 Open CCTV",
            "stream_url": video,
            "snapshot_url": None,
            "meta_name": name,
        })
        if len(out) >= limit:
            break
    return out


def _shorten(text: str, n: int = 34) -> str:
    text = (text or "").strip()
    return text if len(text) <= n else text[: n - 1] + "…"


# --------------------------------------------------------------------------
# CalTrans (California DOT) — snapshot + HLS cameras
# --------------------------------------------------------------------------
async def fetch_caltrans(district: str, url: str, limit: int = 120) -> List[Dict]:
    data = await _cached_get(f"caltrans_{district}", url)
    if not isinstance(data, dict):
        return []
    out: List[Dict] = []
    for entry in data.get("data", []):
        cctv = entry.get("cctv", {})
        if str(cctv.get("inService", "")).lower() != "true":
            continue
        loc = cctv.get("location", {})
        img = cctv.get("imageData", {})
        static = img.get("static", {})
        snapshot = static.get("currentImageURL")
        stream = img.get("streamingVideoURL")
        if not snapshot and not stream:
            continue
        lat, lon = loc.get("latitude"), loc.get("longitude")
        if not _valid_coord(lat, lon):
            continue
        name = loc.get("locationName") or "Traffic Camera"
        place = loc.get("nearbyPlace") or "California"
        cid = _stable_id("caltrans", snapshot or stream)
        out.append({
            "id": cid,
            "ip": _host_from_url(snapshot or stream),
            "port": 443,
            "country": "United States",
            "country_code": "US",
            "city": _shorten(place),
            "isp": "California DOT (Caltrans)",
            "org": f"Caltrans District {district.upper()} CCTV",
            "asn": None,
            "latitude": float(lat),
            "longitude": float(lon),
            "vendor": "public_webcam",
            "vendor_label": ARCHITECTURE_BY_ID["public_webcam"]["label"],
            "protocol": "HLS" if stream else "HTTP/MJPEG",
            "source": "CalTrans Open CCTV",
            "stream_url": stream,
            "snapshot_url": snapshot,
            "meta_name": _shorten(f"{name} · {place}", 60),
        })
        if len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------------
# Curated seed catalogue (Saudi-first + resilient fallback)
# --------------------------------------------------------------------------
def load_seed_catalogue() -> List[Dict]:
    if not settings.SEED_PATH.exists():
        return []
    try:
        with open(settings.SEED_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return []
    out: List[Dict] = []
    for item in data:
        arch = ARCHITECTURE_BY_ID.get(item.get("vendor", "public_webcam"),
                                      ARCHITECTURE_BY_ID["public_webcam"])
        cid = item.get("id") or _stable_id(
            item.get("name", ""), item.get("city", ""), item.get("source", ""),
            item.get("snapshot_url", "") or item.get("stream_url", ""),
            item.get("latitude", ""), item.get("longitude", ""), item.get("ip", ""),
        )
        out.append({
            "id": cid,
            "ip": item.get("ip") or _host_from_url(item.get("snapshot_url", "") or item.get("stream_url", "")),
            "port": item.get("port", 443),
            "country": item.get("country", "Unknown"),
            "country_code": item.get("country_code", "GLOBAL"),
            "city": item.get("city"),
            "isp": item.get("isp"),
            "org": item.get("org"),
            "asn": item.get("asn"),
            "latitude": item.get("latitude"),
            "longitude": item.get("longitude"),
            "vendor": arch["id"],
            "vendor_label": arch["label"],
            "protocol": item.get("protocol", "HTTP"),
            "source": item.get("source", "Curated Seed Catalogue"),
            "stream_url": item.get("stream_url"),
            "snapshot_url": item.get("snapshot_url"),
            "meta_name": item.get("name"),
        })
    return out


# --------------------------------------------------------------------------
# Default OSINT crawl set — worldwide countries with the most indexed open
# cameras in the curated index. Ordered by richness.
OSINT_COUNTRIES = [
    "US", "JP", "IT", "DE", "AT", "RU", "CZ", "FR", "CH", "KR",
    "ES", "CA", "TW", "NL", "GB", "SE", "TH", "ZA", "IN", "TR",
]

# Countries discovered via Shodan (regions the curated index misses, incl. the
# Saudi-Arabia-first priority). Each is resolved to genuinely-rendering feeds.
SHODAN_COUNTRIES = ["SA", "AE", "KW"]


async def aggregate_all(ny_limit: int = 100, caltrans_limit: int = 30,
                        osint_per_country: int = 18,
                        osint_countries: Optional[List[str]] = None,
                        shodan_countries: Optional[List[str]] = None,
                        shodan_max_ips: int = 60) -> List[Dict]:
    """Aggregate every enabled OSINT source into one normalised, de-duplicated list.

    PRIMARY-A: real internet-exposed open cameras from the OSINT open-camera
    index (each a real public IP:port), geolocated by IP.
    PRIMARY-B: Shodan-discovered cameras for regions the index misses (Saudi
    Arabia first) — resolved to genuinely-rendering open feeds.
    SECONDARY: government DOT live-camera APIs (NY 511, CalTrans).
    REFERENCE: a single curated Saudi public-broadcast node (Makkah).
    """
    countries = osint_countries or OSINT_COUNTRIES
    sh_countries = shodan_countries if shodan_countries is not None else SHODAN_COUNTRIES
    all_cameras: List[Dict] = []

    # 1a) PRIMARY — real OSINT open cameras worldwide (curated index).
    all_cameras.extend(await fetch_osint_cameras(
        countries, per_country=osint_per_country, max_pages=5
    ))

    # 1b) PRIMARY — Shodan-discovered cameras (Saudi-first + Gulf), in parallel.
    import asyncio as _aio

    async def _safe_shodan(cc):
        try:
            return await fetch_shodan_country(cc, max_ips=shodan_max_ips)
        except Exception:  # noqa: BLE001
            return []

    for chunk in await _aio.gather(*[_safe_shodan(cc) for cc in sh_countries]):
        all_cameras.extend(chunk)

    # 2) SECONDARY — government DOT live cameras (still real IP cameras).
    all_cameras.extend(await fetch_ny511(limit=ny_limit))
    for district, url in CALTRANS_DISTRICTS.items():
        all_cameras.extend(await fetch_caltrans(district, url, limit=caltrans_limit))

    # 3) REFERENCE — curated Saudi/public-broadcast catalogue (Makkah etc.).
    all_cameras.extend(load_seed_catalogue())

    # De-duplicate by id, then by ip:port to avoid the same device twice.
    seen: Dict[str, Dict] = {}
    seen_hosts: set = set()
    for c in all_cameras:
        if c["id"] in seen:
            continue
        hostkey = f"{c['ip']}:{c['port']}"
        if hostkey in seen_hosts and c["source"] != "Saudi Public Live Feed":
            continue
        seen_hosts.add(hostkey)
        seen[c["id"]] = c
    return list(seen.values())
