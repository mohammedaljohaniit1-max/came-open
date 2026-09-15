"""CAMRADAR REST API routes."""
from __future__ import annotations

import asyncio
import re
from urllib.parse import quote, urljoin, urlparse
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Query, Response
from fastapi.responses import JSONResponse

from ..core import database as db
from ..core.knowledge import (
    CAMERA_ARCHITECTURES,
    COUNTRIES,
    DEFAULT_CREDENTIALS,
    SAUDI_CITIES,
    SAUDI_ISPS,
    SECURITY_TIERS,
)
from ..core.models import PingRequest, ScanRequest
from ..engines.validator import full_probe
from ..services import scan_service
from ..services import shodan_service

router = APIRouter(prefix="/api", tags=["camradar"])


@router.get("/meta")
async def meta():
    """Static reference data for populating UI filters."""
    return {
        "architectures": CAMERA_ARCHITECTURES,
        "countries": COUNTRIES,
        "security_tiers": SECURITY_TIERS,
        "saudi_isps": SAUDI_ISPS,
        "saudi_cities": SAUDI_CITIES,
        "default_credentials": DEFAULT_CREDENTIALS,
    }


@router.post("/scan")
async def scan(req: ScanRequest):
    """
    Run the Smart Pre-Flight scan pipeline:
    aggregate public OSINT sources -> validate reachability -> classify.
    """
    await scan_service.run_scan(persist=True)
    cams = await db.get_cameras(
        country_code=req.country_code,
        vendor=req.architecture,
        only_active=req.only_active,
        exclude_locked=req.exclude_locked,
        require_render=True,
        limit=req.limit,
    )
    return {"count": len(cams), "cameras": cams}


@router.get("/cameras")
async def cameras(
    country_code: str = Query("SA"),
    architecture: str = Query("all"),
    only_active: bool = Query(True),
    exclude_locked: bool = Query(True),
    require_render: bool = Query(True),
    limit: int = Query(60, le=1000),
):
    """Return cached cameras with filters (no re-scan)."""
    total = await db.count_cameras()
    if total == 0:
        # First run: populate the catalogue automatically.
        await scan_service.run_scan(persist=True)
    cams = await db.get_cameras(
        country_code=country_code,
        vendor=architecture,
        only_active=only_active,
        exclude_locked=exclude_locked,
        require_render=require_render,
        limit=limit,
    )
    return {"count": len(cams), "cameras": cams}


@router.post("/ping")
async def ping(req: PingRequest):
    """Fast Ping Test: re-probe selected (or all) cameras and return telemetry."""
    results = await scan_service.reprobe(req.ids or None)
    return {"count": len(results), "results": results}


@router.get("/probe")
async def probe(ip: str = Query(...), port: int = Query(...)):
    """One-off live probe of an arbitrary host:port (Inspect HUD)."""
    return await full_probe(ip, port)


@router.get("/enrich/{ip}")
async def enrich(ip: str):
    """Shodan single-host enrichment (credit-free /shodan/host/{ip})."""
    return await shodan_service.enrich_host(ip)


@router.get("/shodan/count")
async def shodan_count(
    query: str = Query(...), facets: Optional[str] = Query(None)
):
    """Shodan distribution stats (credit-free /shodan/host/count)."""
    return await shodan_service.host_count(query, facets)


@router.get("/stats")
async def stats(country_code: str = Query("SA")):
    """Aggregated telemetry for the analytics charts."""
    return await db.get_stats(country_code if country_code != "GLOBAL" else None)


async def _extract_jpeg(url: str, timeout: float = 8.0) -> Optional[bytes]:
    """Fetch one JPEG frame from a direct image OR a multipart MJPEG stream."""
    async with httpx.AsyncClient(verify=False, timeout=timeout,
                                 follow_redirects=True) as client:
        async with client.stream("GET", url,
                                 headers={"User-Agent": "CAMRADAR/1.0"}) as resp:
            if resp.status_code != 200:
                return None
            ctype = resp.headers.get("content-type", "").lower()
            # Direct single JPEG.
            if ctype.startswith("image"):
                data = await resp.aread()
                return data if data[:2] == b"\xff\xd8" else None
            # Multipart MJPEG: read until we capture one complete JPEG.
            buf = b""
            async for chunk in resp.aiter_bytes():
                buf += chunk
                soi = buf.find(b"\xff\xd8")
                if soi != -1:
                    eoi = buf.find(b"\xff\xd9", soi + 2)
                    if eoi != -1:
                        return buf[soi:eoi + 2]
                if len(buf) > 4_000_000:
                    break
    return None


@router.get("/snapshot")
async def snapshot(url: str = Query(...)):
    """
    Server-side snapshot proxy.

    Extracts a single JPEG frame from either a direct image endpoint or a
    multipart MJPEG stream, so the 16-view wall can display every open camera on
    one origin (bypassing the browser HTTP/1.1 6-connection limit) regardless of
    the camera's native format, CORS policy, or http/https mismatch.
    """
    if not url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid URL scheme")
    try:
        frame = await _extract_jpeg(url)
        if frame:
            return Response(content=frame, media_type="image/jpeg",
                            headers={"Cache-Control": "no-store",
                                     "Access-Control-Allow-Origin": "*"})
        raise HTTPException(status_code=502, detail="No decodable frame")
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=504, detail=f"Fetch failed: {type(exc).__name__}")


# ---------------------------------------------------------------------------
# HLS live-stream proxy
# ---------------------------------------------------------------------------
# Rewrites .m3u8 manifests so that every child playlist and .ts segment is also
# fetched through this proxy. This guarantees in-browser playback for streams
# that lack CORS headers, normalises mixed-content (http upstream on an https
# page), and keeps all traffic on a single origin (bypassing the HTTP/1.1
# 6-connection-per-host browser limit on the 16-view wall).
_ALLOWED_STREAM_HOSTS = re.compile(
    r"(skyvdn\.com|dot\.ca\.gov|holol\.com|itworkscdn\.net|"
    r"austinmobility\.io|wzmedia\.dot\.ca\.gov|nysdot|\.gov)", re.I
)


def _proxied(u: str) -> str:
    return f"/api/hls?url={quote(u, safe='')}"


@router.get("/hls")
async def hls_proxy(url: str = Query(...)):
    """Proxy + rewrite HLS manifests and pass through media segments."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Invalid URL scheme")
    if not _ALLOWED_STREAM_HOSTS.search(parsed.netloc):
        raise HTTPException(status_code=403, detail="Host not in stream allow-list")

    try:
        async with httpx.AsyncClient(verify=False, timeout=12.0,
                                     follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "CAMRADAR/1.0"})
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=504, detail=f"Stream fetch failed: {type(exc).__name__}")

    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Upstream {resp.status_code}")

    ctype = resp.headers.get("content-type", "").lower()
    is_manifest = url.lower().split("?")[0].endswith(".m3u8") or "mpegurl" in ctype

    if is_manifest:
        text = resp.text
        base = url.rsplit("/", 1)[0] + "/"
        out_lines = []
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                # Rewrite URIs embedded in tags (e.g. #EXT-X-MEDIA:...URI="...")
                if 'URI="' in s:
                    def _rw(m):
                        abs_u = urljoin(base, m.group(1))
                        return f'URI="{_proxied(abs_u)}"'
                    s = re.sub(r'URI="([^"]+)"', _rw, s)
                out_lines.append(s)
                continue
            abs_u = urljoin(base, s)
            out_lines.append(_proxied(abs_u))
        body = "\n".join(out_lines) + "\n"
        return Response(content=body, media_type="application/vnd.apple.mpegurl",
                        headers={"Cache-Control": "no-store",
                                 "Access-Control-Allow-Origin": "*"})

    # Media segment (.ts / .m4s / key) — pass through bytes.
    media_type = ctype or "video/mp2t"
    return Response(content=resp.content, media_type=media_type,
                    headers={"Cache-Control": "no-store",
                             "Access-Control-Allow-Origin": "*"})


@router.get("/health")
async def health():
    return {"status": "online", "cameras_cached": await db.count_cameras()}
