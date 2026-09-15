"""
CAMRADAR knowledge base.

Static intelligence used to *classify and audit* exposed camera assets:
  - Camera architectures / vendor fingerprints and their typical ports/protocols.
  - Documented factory default credentials (for EXPOSURE ANALYSIS & AUDIT only).
  - Saudi Arabia ISP / ASN and city reference data (geo-priority).
  - Security classification tiers.

IMPORTANT (ethics): the default-credential table below is reference documentation
used to *flag* devices whose banners match vendors known to ship weak defaults.
CAMRADAR never attempts to authenticate into third-party devices with these
credentials. It is an Attack-Surface-Management knowledge artefact, equivalent
to a vulnerability signature database.
"""
from __future__ import annotations

from typing import Dict, List

# ---------------------------------------------------------------------------
# Camera architectures / vendor fingerprints
# ---------------------------------------------------------------------------
# Each entry documents ports, protocols and banner substrings used to
# fingerprint the device family during banner-grabbing.
CAMERA_ARCHITECTURES: List[Dict] = [
    {
        "id": "hikvision",
        "label": "Hikvision IP Cameras & NVRs",
        "ports": [80, 554, 8000],
        "protocols": ["ISAPI", "RTSP", "HTTP"],
        "banner_signatures": ["hikvision", "app-webs", "dvrdvs", "webs"],
        "snapshot_path": "/ISAPI/Streaming/channels/101/picture",
    },
    {
        "id": "dahua",
        "label": "Dahua Technology DVR/NVR",
        "ports": [80, 554, 37777],
        "protocols": ["RPC", "RTSP", "HTTP"],
        "banner_signatures": ["dahua", "webserver", "sonia"],
        "snapshot_path": "/cgi-bin/snapshot.cgi",
    },
    {
        "id": "axis",
        "label": "Axis Communications",
        "ports": [80, 554],
        "protocols": ["VAPIX", "MJPEG", "RTSP"],
        "banner_signatures": ["axis", "vapix", "boa"],
        "snapshot_path": "/axis-cgi/jpg/image.cgi",
    },
    {
        "id": "netwave",
        "label": "Netwave Wireless IP Cameras",
        "ports": [80, 81],
        "protocols": ["HTTP", "MJPEG"],
        "banner_signatures": ["netwave", "gomax", "ipcamera"],
        "snapshot_path": "/snapshot.cgi",
    },
    {
        "id": "foscam",
        "label": "Foscam IP Cameras",
        "ports": [88, 8080],
        "protocols": ["CGI", "HTTP"],
        "banner_signatures": ["foscam", "ipcam client", "cgiproxy"],
        "snapshot_path": "/snapshot.cgi",
    },
    {
        "id": "dlink",
        "label": "D-Link Video Surveillance",
        "ports": [80, 8080],
        "protocols": ["HTTP", "MJPEG"],
        "banner_signatures": ["d-link", "dcs", "alphapd"],
        "snapshot_path": "/image/jpeg.cgi",
    },
    {
        "id": "webcamxp",
        "label": "WebcamXP / Yawcam Streaming Servers",
        "ports": [80, 8080, 8081],
        "protocols": ["HTTP", "MJPEG"],
        "banner_signatures": ["webcamxp", "webcam 7", "yawcam"],
        "snapshot_path": "/cam_1.jpg",
    },
    {
        "id": "rtsp_gateway",
        "label": "Direct RTSP Video Gateways",
        "ports": [554],
        "protocols": ["RTSP"],
        # Only match explicit RTSP server banners, never generic web words.
        "banner_signatures": ["live555", "rtsp/1.0", "gstreamer rtsp"],
        "snapshot_path": None,
    },
    {
        "id": "public_webcam",
        "label": "Verified Public Webcam Feeds",
        "ports": [80, 443],
        "protocols": ["HTTP", "HTTPS", "MJPEG"],
        "banner_signatures": ["nginx", "apache", "cloudflare"],
        "snapshot_path": None,
    },
]

ARCHITECTURE_BY_ID: Dict[str, Dict] = {a["id"]: a for a in CAMERA_ARCHITECTURES}


# ---------------------------------------------------------------------------
# Factory default-credential reference (AUDIT / EXPOSURE ANALYSIS ONLY)
# ---------------------------------------------------------------------------
DEFAULT_CREDENTIALS: Dict[str, List[str]] = {
    "hikvision": ["admin:12345", "admin:admin", "admin:123456"],
    "dahua": ["admin:admin", "888888:888888", "666666:666666"],
    "axis": ["root:root", "root:pass", "admin:admin"],
    "foscam": ["admin:(blank)", "admin:admin"],
    "netwave": ["admin:(blank)", "admin:admin"],
    "dlink": ["admin:(blank)", "admin:admin"],
}


# ---------------------------------------------------------------------------
# Security classification tiers
# ---------------------------------------------------------------------------
SECURITY_TIERS = {
    "open": {
        "code": "OPEN_ACCESS",
        "label": "Open Access",
        "color": "#00ff88",
        "icon": "unlock",
        "description": "Publicly viewable stream, no authentication required.",
    },
    "default_creds": {
        "code": "DEFAULT_CREDS_RISK",
        "label": "Default Credentials Risk",
        "color": "#ffb800",
        "icon": "triangle-exclamation",
        "description": "Vendor known to ship weak factory defaults; flagged for audit.",
    },
    "locked": {
        "code": "AUTH_LOCKED",
        "label": "Auth Locked (401/403)",
        "color": "#ff3b5c",
        "icon": "lock",
        "description": "Device demands custom authentication; stream is protected.",
    },
    "dead": {
        "code": "OFFLINE",
        "label": "Offline / Dead",
        "color": "#4a5568",
        "icon": "plug-circle-xmark",
        "description": "Host did not respond to the pre-flight probe.",
    },
}


# ---------------------------------------------------------------------------
# Saudi Arabia geo-priority reference data
# ---------------------------------------------------------------------------
SAUDI_ISPS: List[Dict] = [
    {"id": "stc", "name": "STC (Saudi Telecom Company)", "asn": "AS39386"},
    {"id": "mobily", "name": "Mobily (Etihad Etisalat)", "asn": "AS35819"},
    {"id": "zain", "name": "Zain KSA", "asn": "AS59605"},
    {"id": "salam", "name": "Salam Telecom (ITC)", "asn": "AS8895"},
    {"id": "atheeb", "name": "Atheeb / GO Telecom", "asn": "AS43766"},
]

SAUDI_CITIES: Dict[str, Dict] = {
    "Riyadh": {"lat": 24.7136, "lon": 46.6753},
    "Jeddah": {"lat": 21.4858, "lon": 39.1925},
    "Dammam": {"lat": 26.4207, "lon": 50.0888},
    "Makkah": {"lat": 21.3891, "lon": 39.8579},
    "Medina": {"lat": 24.5247, "lon": 39.5692},
    "Khobar": {"lat": 26.2794, "lon": 50.2083},
    "Tabuk": {"lat": 28.3838, "lon": 36.5550},
    "Abha": {"lat": 18.2465, "lon": 42.5117},
    "Buraidah": {"lat": 26.3260, "lon": 43.9750},
}

# Countries available in the region toggle. SA is always the default.
COUNTRIES: List[Dict] = [
    {"code": "SA", "name": "Saudi Arabia", "lat": 24.7136, "lon": 46.6753, "zoom": 6},
    {"code": "AE", "name": "United Arab Emirates", "lat": 24.4539, "lon": 54.3773, "zoom": 7},
    {"code": "KW", "name": "Kuwait", "lat": 29.3759, "lon": 47.9774, "zoom": 8},
    {"code": "US", "name": "United States", "lat": 39.8283, "lon": -98.5795, "zoom": 4},
    {"code": "DE", "name": "Germany", "lat": 51.1657, "lon": 10.4515, "zoom": 5},
    {"code": "JP", "name": "Japan", "lat": 36.2048, "lon": 138.2529, "zoom": 5},
    {"code": "GLOBAL", "name": "Global View", "lat": 20.0, "lon": 10.0, "zoom": 2},
]
