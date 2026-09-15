"""
Scan orchestration service.

Pipeline (the CAMRADAR "Smart Pre-Flight" workflow):
    aggregate() -> validate() -> classify() -> persist()

  1. Aggregate normalised camera records from public OSINT sources.
  2. Run the async Pre-Flight Validator on every record (real reachability).
  3. Merge probe telemetry + security classification onto each record.
  4. Persist to SQLite and return the enriched list.

Shodan enrichment is performed lazily (per-host, on demand) via the enrich
route to respect the OSS-plan credit constraints.
"""
from __future__ import annotations

import asyncio
from typing import Dict, List, Optional

from ..core import database as db
from ..engines.validator import batch_probe, batch_verify_render
from . import aggregator

# Simple in-process guard so two concurrent scans don't stampede the sources.
_scan_lock = asyncio.Lock()


def _merge_probe(camera: Dict, probe: Dict) -> Dict:
    # Shodan-discovered nodes carry their own authoritative auth-tier
    # classification (open / default_creds / locked) — preserve it rather than
    # overwrite with the generic TCP-probe classification.
    preset_tier = camera.get("source") == "Shodan OSINT Discovery"
    camera.update({
        "alive": probe["alive"],
        "port_status": probe["port_status"],
        "rtt_ms": probe["rtt_ms"],
        "signal_pct": probe["signal_pct"],
        "signal_label": probe["signal_label"],
        "packet_loss_pct": probe["packet_loss_pct"],
        "last_checked": probe["checked_at"],
    })
    if not preset_tier:
        camera.update({
            "http_status": probe.get("http_status"),
            "security_tier": probe["security_tier"],
            "security_code": probe["security_code"],
            "default_creds": probe.get("default_creds", []),
        })
    else:
        # attach default-cred reference for the detected vendor if any
        from ..core.knowledge import DEFAULT_CREDENTIALS
        if camera.get("security_tier") == "default_creds" and not camera.get("default_creds"):
            camera["default_creds"] = DEFAULT_CREDENTIALS.get("hikvision", [])
    # If the validator fingerprinted a specific *device vendor* from the banner
    # (Hikvision, Dahua, Axis, ...), and our source only had the generic
    # public_webcam tag, upgrade it. We never downgrade a verified public feed
    # to the generic rtsp_gateway class based on a fuzzy banner match.
    _DEVICE_VENDORS = {"hikvision", "dahua", "axis", "netwave", "foscam", "dlink", "webcamxp"}
    detected = probe.get("detected_vendor")
    if detected in _DEVICE_VENDORS and camera.get("vendor") == "public_webcam":
        from ..core.knowledge import ARCHITECTURE_BY_ID
        arch = ARCHITECTURE_BY_ID.get(detected)
        if arch:
            camera["vendor"] = arch["id"]
            camera["vendor_label"] = arch["label"]
    return camera


async def run_scan(
    ny_limit: int = 120,
    caltrans_limit: int = 40,
    osint_per_country: int = 24,
    osint_countries=None,
    persist: bool = True,
) -> List[Dict]:
    """Aggregate + pre-flight validate + RENDER-VERIFY + classify the catalogue.

    The render-verify stage fetches an actual frame from every camera feed and
    keeps only those that produce a decodable JPEG *right now*, so the dashboard
    never displays a dead feed, a "no signal" placeholder, or a fake image.
    """
    async with _scan_lock:
        cameras = await aggregator.aggregate_all(
            ny_limit=ny_limit, caltrans_limit=caltrans_limit,
            osint_per_country=osint_per_country, osint_countries=osint_countries,
        )
        if not cameras:
            return []

        # Stage 1 — TCP pre-flight probe (RTT / port / banner / classify).
        targets = [{"id": c["id"], "ip": c["ip"], "port": c["port"]} for c in cameras]
        probes = await batch_probe(targets)
        probe_by_id = {p["id"]: p for p in probes}

        enriched: List[Dict] = []
        for c in cameras:
            probe = probe_by_id.get(c["id"])
            if probe:
                c = _merge_probe(c, probe)
            enriched.append(c)

        # Stage 2 — RENDER VERIFICATION. Only for alive HTTP snapshot/MJPEG feeds
        # (HLS broadcast nodes are verified by the browser player instead).
        render_targets = [
            {"id": c["id"], "feed_url": c.get("feed_url") or c.get("snapshot_url")}
            for c in enriched
            if c.get("alive") and (c.get("feed_url") or c.get("snapshot_url"))
        ]
        render_map = await batch_verify_render(render_targets)
        for c in enriched:
            r = render_map.get(c["id"])
            if r:
                c["renders"] = bool(r.get("renders"))
                if r.get("renders"):
                    # A rendering open feed is confirmed OPEN_ACCESS.
                    c["security_tier"] = "open"
                    c["security_code"] = "OPEN_ACCESS"
            else:
                # HLS/broadcast nodes have no snapshot to pre-render.
                c["renders"] = bool(c.get("stream_url"))

        # Stage 3 — CVE EXPLOITABILITY ASSESSMENT (detection & reporting only).
        from ..core.cve_kb import assess_risk
        for c in enriched:
            risk = assess_risk(
                vendor=c.get("vendor"),
                reported_vulns=c.get("shodan_vulns", []),
                ports=c.get("shodan_ports", []) or [c.get("port")],
                security_tier=c.get("security_tier", "dead"),
            )
            c["risk_level"] = risk["risk_level"]
            c["risk_score"] = risk["risk_score"]
            c["cve_count"] = risk["cve_count"]
            c["cve_findings"] = risk["findings"]

        if persist:
            await db.upsert_cameras(enriched)
        return enriched


async def reprobe(camera_ids: Optional[List[str]] = None) -> List[Dict]:
    """Re-run the Pre-Flight Validator on specific cameras (Fast Ping Test)."""
    if camera_ids:
        rows = [await db.get_camera(cid) for cid in camera_ids]
        rows = [r for r in rows if r]
    else:
        rows = await db.get_cameras(limit=1000)

    if not rows:
        return []

    targets = [{"id": r["id"], "ip": r["ip"], "port": r["port"]} for r in rows]
    probes = await batch_probe(targets)

    results: List[Dict] = []
    for p in probes:
        await db.update_probe(p["id"], {
            "alive": int(p["alive"]),
            "port_status": p["port_status"],
            "rtt_ms": p["rtt_ms"],
            "signal_pct": p["signal_pct"],
            "signal_label": p["signal_label"],
            "packet_loss_pct": p["packet_loss_pct"],
            "http_status": p.get("http_status"),
            "security_tier": p["security_tier"],
            "security_code": p["security_code"],
            "last_checked": p["checked_at"],
        })
        results.append({
            "id": p["id"],
            "alive": p["alive"],
            "port_status": p["port_status"],
            "rtt_ms": p["rtt_ms"],
            "signal_pct": p["signal_pct"],
            "signal_label": p["signal_label"],
            "packet_loss_pct": p["packet_loss_pct"],
            "security_tier": p["security_tier"],
            "security_code": p["security_code"],
        })
    return results
