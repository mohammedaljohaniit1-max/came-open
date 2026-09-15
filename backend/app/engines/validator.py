"""
CAMRADAR Pre-Flight Availability Validator (the flagship engine).

Solves the #1 weakness of Shodan/Insecam: stale, dead IPs. Before any node is
rendered on the dashboard, this engine performs a *real* lightweight probe:

  1. Asynchronous TCP connect handshake (non-blocking, high concurrency).
  2. Precise RTT / latency measurement (perf_counter around the connect).
  3. Real port status classification: OPEN / FILTERED / CLOSED.
  4. Signal-quality and packet-loss derivation from RTT + reachability.
  5. Real HTTP banner grabbing (Server header + response line) for vendor
     fingerprinting and 401/403 auth-lock detection.

All measurements are genuine network facts — nothing is fabricated. A host that
does not answer is reported as OFFLINE, never as a fake live stream.
"""
from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

import httpx

from ..core.config import settings
from ..core.knowledge import CAMERA_ARCHITECTURES, DEFAULT_CREDENTIALS


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _signal_from_rtt(rtt_ms: Optional[float], alive: bool) -> Dict:
    """Derive human-readable signal quality from measured RTT."""
    if not alive or rtt_ms is None:
        return {"signal_pct": 0, "signal_label": "NO SIGNAL", "packet_loss_pct": 100}

    # Map RTT to a 0-100 quality score. <=50ms => excellent, degrade to ~1000ms.
    if rtt_ms <= 50:
        pct = 100
    elif rtt_ms >= 1000:
        pct = 40
    else:
        # Linear-ish falloff between 50ms (100%) and 1000ms (40%).
        pct = int(round(100 - (rtt_ms - 50) * (60.0 / 950.0)))
    pct = max(0, min(100, pct))

    if pct > 95:
        label = "EXCELLENT"
    elif pct >= 80:
        label = "GOOD"
    else:
        label = "WEAK"
    return {"signal_pct": pct, "signal_label": label, "packet_loss_pct": 0}


def _fingerprint_vendor(server_header: str, body_snippet: str) -> Optional[str]:
    """
    Match banner text against known vendor signatures using word-boundary
    matching to avoid false positives (e.g. generic 'webs' matching nginx).

    Generic web-server banners (nginx/apache/cloudflare) are treated as public
    webcam infrastructure, never as a specific camera vendor.
    """
    haystack = f"{server_header} {body_snippet}".lower()

    # Generic infrastructure servers => public webcam, not a device vendor.
    generic = ("nginx", "apache", "cloudflare", "microsoft-iis", "openresty",
               "envoy", "caddy", "lighttpd", "amazon", "gws")
    if any(g in server_header.lower() for g in generic):
        return None

    for arch in CAMERA_ARCHITECTURES:
        if arch["id"] == "public_webcam":
            continue
        for sig in arch["banner_signatures"]:
            # Require the signature as a whole token, not a random substring.
            if re.search(rf"(?<![a-z0-9]){re.escape(sig)}(?![a-z0-9])", haystack):
                return arch["id"]
    return None


async def tcp_probe(ip: str, port: int, timeout: Optional[float] = None) -> Dict:
    """Perform a single asynchronous TCP connect probe with RTT measurement."""
    timeout = timeout or settings.probe_timeout_s
    start = time.perf_counter()
    port_status = "CLOSED"
    alive = False
    rtt_ms: Optional[float] = None

    try:
        fut = asyncio.open_connection(host=ip, port=port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        rtt_ms = round((time.perf_counter() - start) * 1000.0, 2)
        alive = True
        port_status = "OPEN"
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
        except (asyncio.TimeoutError, Exception):
            pass
    except asyncio.TimeoutError:
        # No RST and no SYN-ACK within the window => firewalled / filtered.
        port_status = "FILTERED"
    except (ConnectionRefusedError, OSError):
        # Active refusal (RST) => port closed but host reachable.
        port_status = "CLOSED"
    except Exception:
        port_status = "FILTERED"

    signal = _signal_from_rtt(rtt_ms, alive)
    return {
        "ip": ip,
        "port": port,
        "alive": alive,
        "port_status": port_status,
        "rtt_ms": rtt_ms,
        **signal,
        "checked_at": _now_iso(),
    }


async def http_banner_grab(
    ip: str, port: int, timeout: Optional[float] = None
) -> Dict:
    """
    Real HTTP banner grab: fetch headers/status to detect auth-lock (401/403)
    and fingerprint the vendor from the Server header.

    NOTE: This is a passive metadata read (HEAD/GET of the root path). It never
    submits credentials and never attempts authentication.
    """
    timeout = timeout or settings.probe_timeout_s
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    result: Dict = {
        "http_status": None,
        "server_header": None,
        "banner": None,
        "detected_vendor": None,
    }
    try:
        async with httpx.AsyncClient(
            verify=False, timeout=timeout, follow_redirects=False
        ) as client:
            resp = await client.get(url, headers={"User-Agent": "CAMRADAR-PreFlight/1.0"})
            server = resp.headers.get("server", "")
            www_auth = resp.headers.get("www-authenticate", "")
            body_snip = ""
            try:
                body_snip = resp.text[:512]
            except Exception:
                body_snip = ""
            result["http_status"] = resp.status_code
            result["server_header"] = server or None
            banner = f"HTTP {resp.status_code} {resp.reason_phrase}".strip()
            if server:
                banner += f" | Server: {server}"
            if www_auth:
                banner += f" | Auth: {www_auth[:60]}"
            result["banner"] = banner
            result["detected_vendor"] = _fingerprint_vendor(server, body_snip)
    except Exception as exc:  # noqa: BLE001
        result["banner"] = f"No HTTP banner ({type(exc).__name__})"
    return result


def classify_security(http_status: Optional[int], alive: bool, vendor: Optional[str]) -> Dict:
    """
    Classify the security posture from real probe evidence.

    - Not alive               -> dead / OFFLINE
    - 401 / 403               -> locked / AUTH_LOCKED
    - 200 + weak-default vendor-> default_creds / DEFAULT_CREDS_RISK (audit flag)
    - 200 (open)              -> open / OPEN_ACCESS
    """
    if not alive:
        return {"security_tier": "dead", "security_code": "OFFLINE", "default_creds": []}

    if http_status in (401, 403):
        return {"security_tier": "locked", "security_code": "AUTH_LOCKED", "default_creds": []}

    if http_status and 200 <= http_status < 400:
        if vendor and vendor in DEFAULT_CREDENTIALS:
            return {
                "security_tier": "default_creds",
                "security_code": "DEFAULT_CREDS_RISK",
                "default_creds": DEFAULT_CREDENTIALS[vendor],
            }
        return {"security_tier": "open", "security_code": "OPEN_ACCESS", "default_creds": []}

    # Reachable at TCP layer but no clean HTTP answer -> treat as open TCP service.
    return {"security_tier": "open", "security_code": "OPEN_ACCESS", "default_creds": []}


async def full_probe(ip: str, port: int) -> Dict:
    """Combined probe: TCP handshake + (if alive) HTTP banner + classification."""
    tcp = await tcp_probe(ip, port)
    http_meta = {"http_status": None, "server_header": None, "banner": None, "detected_vendor": None}
    if tcp["alive"] and port not in (554, 37777):
        # Skip HTTP grab on pure RTSP/RPC ports.
        http_meta = await http_banner_grab(ip, port)
    sec = classify_security(http_meta["http_status"], tcp["alive"], http_meta["detected_vendor"])
    return {**tcp, **http_meta, **sec}


async def batch_probe(targets: List[Dict], concurrency: Optional[int] = None) -> List[Dict]:
    """
    Probe many targets concurrently with a bounded semaphore.

    Each target: {"id": ..., "ip": ..., "port": ...}
    Returns list of {"id": ..., <probe fields>}.
    """
    concurrency = concurrency or settings.PROBE_CONCURRENCY
    sem = asyncio.Semaphore(concurrency)

    async def _one(t: Dict) -> Dict:
        async with sem:
            probe = await full_probe(t["ip"], t["port"])
            probe["id"] = t.get("id")
            return probe

    return await asyncio.gather(*[_one(t) for t in targets])


async def verify_render(feed_url: str, timeout: float = 6.0) -> Dict:
    """
    Confirm a camera feed actually serves a decodable live frame RIGHT NOW.

    Fetches the snapshot / first MJPEG frame and validates it is a real JPEG
    (magic bytes 0xFFD8). This guarantees the dashboard never shows a dead feed
    or a "no signal" placeholder — only cameras that produce a genuine image
    pass. Works for both single-shot JPEG endpoints and multipart MJPEG streams
    (we read just enough bytes to find one JPEG frame, then abort).

    Returns {"renders": bool, "frame_bytes": int, "content_type": str}.
    """
    result = {"renders": False, "frame_bytes": 0, "content_type": None}
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout,
                                     follow_redirects=True) as client:
            async with client.stream("GET", feed_url,
                                     headers={"User-Agent": "CAMRADAR/1.0"}) as resp:
                if resp.status_code != 200:
                    result["http_status"] = resp.status_code
                    return result
                ctype = resp.headers.get("content-type", "")
                result["content_type"] = ctype
                buf = b""
                async for chunk in resp.aiter_bytes():
                    buf += chunk
                    # Look for a full JPEG (SOI ... EOI) within the buffer.
                    soi = buf.find(b"\xff\xd8")
                    if soi != -1:
                        eoi = buf.find(b"\xff\xd9", soi + 2)
                        if eoi != -1:
                            result["renders"] = True
                            result["frame_bytes"] = eoi - soi + 2
                            return result
                    if len(buf) > 3_000_000:  # 3MB cap — enough for one frame
                        break
                # Some snapshot endpoints send a complete small JPEG in one shot.
                if buf[:2] == b"\xff\xd8":
                    result["renders"] = True
                    result["frame_bytes"] = len(buf)
    except Exception:  # noqa: BLE001
        pass
    return result


async def batch_verify_render(targets: List[Dict],
                              concurrency: int = 40) -> Dict[str, Dict]:
    """Verify many feeds render concurrently. targets: [{id, feed_url}]. """
    sem = asyncio.Semaphore(concurrency)

    async def _one(t: Dict) -> tuple:
        async with sem:
            r = await verify_render(t["feed_url"])
            return t["id"], r

    pairs = await asyncio.gather(*[_one(t) for t in targets if t.get("feed_url")])
    return {cid: r for cid, r in pairs}


# Candidate open-snapshot / MJPEG paths tried when a discovered IP has no known
# feed URL. NONE of these submit credentials; they only request the paths that
# many cameras expose publicly. The first that returns a decodable JPEG wins.
# Ordered by real-world hit-rate to fail fast.
_CANDIDATE_PATHS = [
    "/mjpg/video.mjpg",
    "/video.mjpg",
    "/SnapshotJPEG?Resolution=640x480",
    "/snapshot.cgi",
    "/tmpfs/auto.jpg",
    "/cgi-bin/snapshot.cgi",
    "/axis-cgi/mjpg/video.cgi",
    "/webcapture.jpg?command=snap&channel=1",
    "/onvif-http/snapshot",
]


async def find_working_feed(ip: str, ports: List[int],
                            timeout: float = 3.0) -> Optional[Dict]:
    """
    Try candidate snapshot/MJPEG paths across an IP's open web ports and return
    the first that serves a decodable live JPEG frame. Probes run concurrently
    per host so a slow/dead path never blocks the others. Returns
    {"feed_url":..., "port":..., "protocol":...} or None if nothing renders.
    """
    web_ports = [p for p in ports if 80 <= p <= 9100] or [80]
    urls = [(f"http://{ip}:{port}{path}", port, path)
            for port in web_ports[:2] for path in _CANDIDATE_PATHS]

    async def _try(url, port, path):
        r = await verify_render(url, timeout=timeout)
        if r.get("renders"):
            proto = "MJPEG" if ".mjpg" in path or "video" in path else "HTTP/JPEG"
            return {"feed_url": url, "port": port, "protocol": proto}
        return None

    # Fire all candidate probes concurrently; return the first success.
    results = await asyncio.gather(*[_try(u, p, pa) for u, p, pa in urls])
    for r in results:
        if r:
            return r
    return None
