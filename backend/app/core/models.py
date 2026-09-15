"""Pydantic data models for CAMRADAR API contracts."""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class ProbeResult(BaseModel):
    """Result of a single pre-flight TCP/HTTP probe."""

    ip: str
    port: int
    alive: bool
    port_status: str = Field(description="OPEN | FILTERED | CLOSED")
    rtt_ms: Optional[float] = None
    signal_pct: int = 0
    signal_label: str = "NO SIGNAL"
    packet_loss_pct: int = 100
    http_status: Optional[int] = None
    banner: Optional[str] = None
    server_header: Optional[str] = None
    detected_vendor: Optional[str] = None
    security_tier: str = "dead"
    checked_at: str


class ShodanHost(BaseModel):
    """Subset of enrichment fields from /shodan/host/{ip}."""

    ip: str
    org: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    os: Optional[str] = None
    ports: List[int] = []
    hostnames: List[str] = []
    vulns: List[str] = []
    tags: List[str] = []
    last_update: Optional[str] = None
    error: Optional[str] = None


class Camera(BaseModel):
    """A camera / node record surfaced on the dashboard."""

    id: str
    ip: str
    port: int
    country: str
    country_code: str
    city: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    vendor: str
    vendor_label: str
    protocol: str
    source: str = Field(description="Origin OSINT source of the record")
    stream_url: Optional[str] = None
    snapshot_url: Optional[str] = None

    # Live availability (populated by the validator)
    alive: bool = False
    port_status: str = "UNKNOWN"
    rtt_ms: Optional[float] = None
    signal_pct: int = 0
    signal_label: str = "NO SIGNAL"
    packet_loss_pct: int = 100
    http_status: Optional[int] = None
    security_tier: str = "dead"
    security_code: str = "OFFLINE"
    default_creds: List[str] = []
    last_checked: Optional[str] = None


class ScanRequest(BaseModel):
    country_code: str = "SA"
    architecture: str = "all"
    only_active: bool = True
    exclude_locked: bool = True
    require_render: bool = True
    limit: int = 60


class PingRequest(BaseModel):
    ids: List[str] = Field(default_factory=list, description="Camera ids to re-probe")
