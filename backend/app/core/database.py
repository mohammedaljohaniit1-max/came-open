"""
Async SQLite persistence layer (aiosqlite).

Stores the aggregated camera catalogue and the latest probe telemetry so the
dashboard can serve cached results instantly and record availability history.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional

import aiosqlite

from .config import settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cameras (
    id            TEXT PRIMARY KEY,
    ip            TEXT NOT NULL,
    port          INTEGER NOT NULL,
    country       TEXT,
    country_code  TEXT,
    city          TEXT,
    isp           TEXT,
    org           TEXT,
    asn           TEXT,
    latitude      REAL,
    longitude     REAL,
    vendor        TEXT,
    vendor_label  TEXT,
    protocol      TEXT,
    source        TEXT,
    stream_url    TEXT,
    snapshot_url  TEXT,
    feed_url      TEXT,
    alive         INTEGER DEFAULT 0,
    renders       INTEGER DEFAULT 0,
    port_status   TEXT DEFAULT 'UNKNOWN',
    rtt_ms        REAL,
    signal_pct    INTEGER DEFAULT 0,
    signal_label  TEXT DEFAULT 'NO SIGNAL',
    packet_loss_pct INTEGER DEFAULT 100,
    http_status   INTEGER,
    security_tier TEXT DEFAULT 'dead',
    security_code TEXT DEFAULT 'OFFLINE',
    default_creds TEXT DEFAULT '[]',
    risk_level    TEXT DEFAULT 'LOW',
    risk_score    INTEGER DEFAULT 0,
    cve_count     INTEGER DEFAULT 0,
    cve_findings  TEXT DEFAULT '[]',
    shodan_vulns  TEXT DEFAULT '[]',
    shodan_ports  TEXT DEFAULT '[]',
    last_checked  TEXT
);

CREATE TABLE IF NOT EXISTS probe_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    camera_id   TEXT,
    alive       INTEGER,
    rtt_ms      REAL,
    signal_pct  INTEGER,
    checked_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_cameras_cc ON cameras(country_code);
CREATE INDEX IF NOT EXISTS idx_cameras_vendor ON cameras(vendor);
CREATE INDEX IF NOT EXISTS idx_cameras_tier ON cameras(security_tier);
"""

_LIST_COLUMNS = {"default_creds", "cve_findings", "shodan_vulns", "shodan_ports"}


def _row_to_dict(row: aiosqlite.Row) -> Dict:
    d = dict(row)
    for col in _LIST_COLUMNS:
        if col in d and isinstance(d[col], str):
            try:
                d[col] = json.loads(d[col])
            except (json.JSONDecodeError, TypeError):
                d[col] = []
    d["alive"] = bool(d.get("alive"))
    d["renders"] = bool(d.get("renders"))
    return d


async def init_db() -> None:
    async with aiosqlite.connect(settings.DB_PATH) as db:
        await db.executescript(_SCHEMA)
        await db.commit()


async def upsert_cameras(cameras: List[Dict]) -> None:
    if not cameras:
        return
    async with aiosqlite.connect(settings.DB_PATH) as db:
        for c in cameras:
            await db.execute(
                """
                INSERT INTO cameras (
                    id, ip, port, country, country_code, city, isp, org, asn,
                    latitude, longitude, vendor, vendor_label, protocol, source,
                    stream_url, snapshot_url, feed_url, alive, renders, port_status,
                    rtt_ms, signal_pct, signal_label, packet_loss_pct, http_status,
                    security_tier, security_code, default_creds,
                    risk_level, risk_score, cve_count, cve_findings,
                    shodan_vulns, shodan_ports, last_checked
                ) VALUES (
                    :id, :ip, :port, :country, :country_code, :city, :isp, :org, :asn,
                    :latitude, :longitude, :vendor, :vendor_label, :protocol, :source,
                    :stream_url, :snapshot_url, :feed_url, :alive, :renders, :port_status,
                    :rtt_ms, :signal_pct, :signal_label, :packet_loss_pct, :http_status,
                    :security_tier, :security_code, :default_creds,
                    :risk_level, :risk_score, :cve_count, :cve_findings,
                    :shodan_vulns, :shodan_ports, :last_checked
                )
                ON CONFLICT(id) DO UPDATE SET
                    alive=excluded.alive, renders=excluded.renders,
                    port_status=excluded.port_status,
                    rtt_ms=excluded.rtt_ms, signal_pct=excluded.signal_pct,
                    signal_label=excluded.signal_label,
                    packet_loss_pct=excluded.packet_loss_pct,
                    http_status=excluded.http_status,
                    security_tier=excluded.security_tier,
                    security_code=excluded.security_code,
                    risk_level=excluded.risk_level, risk_score=excluded.risk_score,
                    cve_count=excluded.cve_count, cve_findings=excluded.cve_findings,
                    shodan_vulns=excluded.shodan_vulns, shodan_ports=excluded.shodan_ports,
                    isp=COALESCE(excluded.isp, cameras.isp),
                    org=COALESCE(excluded.org, cameras.org),
                    asn=COALESCE(excluded.asn, cameras.asn),
                    last_checked=excluded.last_checked
                """,
                {
                    "stream_url": None, "snapshot_url": None, "feed_url": None,
                    "renders": 0, "asn": None, "isp": None, "org": None, "city": None,
                    "latitude": None, "longitude": None,
                    "risk_level": "LOW", "risk_score": 0, "cve_count": 0,
                    **c,
                    "alive": int(bool(c.get("alive"))),
                    "renders": int(bool(c.get("renders"))),
                    "default_creds": json.dumps(c.get("default_creds", [])),
                    "cve_findings": json.dumps(c.get("cve_findings", [])),
                    "shodan_vulns": json.dumps(c.get("shodan_vulns", [])),
                    "shodan_ports": json.dumps(c.get("shodan_ports", [])),
                },
            )
        await db.commit()


async def get_cameras(
    country_code: Optional[str] = None,
    vendor: Optional[str] = None,
    only_active: bool = False,
    exclude_locked: bool = False,
    require_render: bool = False,
    limit: int = 500,
) -> List[Dict]:
    query = "SELECT * FROM cameras WHERE 1=1"
    params: List = []
    if country_code and country_code != "GLOBAL":
        query += " AND country_code = ?"
        params.append(country_code)
    if vendor and vendor != "all":
        query += " AND vendor = ?"
        params.append(vendor)
    if only_active:
        query += " AND alive = 1"
    if exclude_locked:
        query += " AND security_tier != 'locked'"
    if require_render:
        # Only feeds that actually produced a live frame, OR HLS/broadcast nodes
        # (verified separately by the player) — never dead/no-signal cells.
        query += " AND (renders = 1 OR stream_url IS NOT NULL)"
    query += " ORDER BY renders DESC, risk_score DESC, alive DESC, signal_pct DESC LIMIT ?"
    params.append(limit)

    async with aiosqlite.connect(settings.DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(query, params)
        rows = await cur.fetchall()
        return [_row_to_dict(r) for r in rows]


async def get_camera(camera_id: str) -> Optional[Dict]:
    async with aiosqlite.connect(settings.DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM cameras WHERE id = ?", (camera_id,))
        row = await cur.fetchone()
        return _row_to_dict(row) if row else None


async def update_probe(camera_id: str, probe: Dict) -> None:
    async with aiosqlite.connect(settings.DB_PATH) as db:
        await db.execute(
            """
            UPDATE cameras SET
                alive=:alive, port_status=:port_status, rtt_ms=:rtt_ms,
                signal_pct=:signal_pct, signal_label=:signal_label,
                packet_loss_pct=:packet_loss_pct, http_status=:http_status,
                security_tier=:security_tier, security_code=:security_code,
                last_checked=:last_checked
            WHERE id=:id
            """,
            {**probe, "id": camera_id},
        )
        await db.execute(
            "INSERT INTO probe_history (camera_id, alive, rtt_ms, signal_pct, checked_at) "
            "VALUES (?,?,?,?,?)",
            (camera_id, int(probe["alive"]), probe.get("rtt_ms"),
             probe.get("signal_pct", 0), probe.get("last_checked")),
        )
        await db.commit()


async def count_cameras() -> int:
    async with aiosqlite.connect(settings.DB_PATH) as db:
        cur = await db.execute("SELECT COUNT(*) FROM cameras")
        (n,) = await cur.fetchone()
        return n


async def get_stats(country_code: Optional[str] = None) -> Dict:
    """Aggregate telemetry for the analytics dashboard."""
    where = ""
    params: List = []
    if country_code and country_code != "GLOBAL":
        where = " WHERE country_code = ?"
        params = [country_code]

    async with aiosqlite.connect(settings.DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        async def grouped(col: str) -> Dict[str, int]:
            cur = await db.execute(
                f"SELECT {col} AS k, COUNT(*) AS c FROM cameras{where} GROUP BY {col}",
                params,
            )
            return {(r["k"] or "unknown"): r["c"] for r in await cur.fetchall()}

        by_vendor = await grouped("vendor_label")
        by_tier = await grouped("security_tier")
        by_port = await grouped("port")
        by_protocol = await grouped("protocol")

        cur = await db.execute(
            f"SELECT COUNT(*) AS total, SUM(alive) AS alive FROM cameras{where}", params
        )
        totals = await cur.fetchone()

    return {
        "total": totals["total"] or 0,
        "alive": totals["alive"] or 0,
        "by_vendor": by_vendor,
        "by_tier": by_tier,
        "by_port": {str(k): v for k, v in by_port.items()},
        "by_protocol": by_protocol,
    }
