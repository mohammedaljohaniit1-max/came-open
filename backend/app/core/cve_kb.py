"""
CAMRADAR CVE Knowledge Base (detection & reporting only).

A curated database of publicly-disclosed, well-documented vulnerabilities that
affect internet-exposed camera / DVR / NVR devices. CAMRADAR uses this purely to
*detect and REPORT* exposure — the same way a vulnerability scanner (Nessus,
OpenVAS) or Shodan itself flags known CVEs. It does NOT exploit anything and
never authenticates to third-party devices.

Why this beats "password cracking":
  Cracking a strong password is illegal, slow, and low-value. Professional
  attack-surface management instead fingerprints the device and cross-references
  KNOWN vulnerabilities — many camera CVEs are *authentication bypasses* or
  *backdoors* that make the password irrelevant. Reporting these to the asset
  owner is the legal, high-impact deliverable.

Each entry documents: CVE id, affected vendor/products, CVSS severity, class,
a one-line description, and a remediation note.
"""
from __future__ import annotations

from typing import Dict, List

# Severity → numeric weight for risk scoring.
SEVERITY_WEIGHT = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 45, "LOW": 20}

# Curated camera-relevant CVE catalogue (public disclosures).
CVE_DB: List[Dict] = [
    {
        "id": "CVE-2017-7921",
        "vendor": "hikvision",
        "products": ["hikvision ip camera", "dvrdvs", "app-webs"],
        "severity": "CRITICAL", "cvss": 10.0, "class": "Authentication Bypass",
        "desc": "Improper authentication lets an unauthenticated attacker escalate "
                "privileges and access device data/streams without the password.",
        "remediation": "Upgrade firmware to V5.4.5+ / V5.5.0+; restrict WAN exposure.",
    },
    {
        "id": "CVE-2021-36260",
        "vendor": "hikvision",
        "products": ["hikvision ip camera", "web server", "app-webs"],
        "severity": "CRITICAL", "cvss": 9.8, "class": "Remote Code Execution",
        "desc": "Command injection in the web server allows unauthenticated RCE via "
                "a crafted message to the device.",
        "remediation": "Apply Hikvision HSRC-202109-01 firmware update immediately.",
    },
    {
        "id": "CVE-2017-7925",
        "vendor": "dahua",
        "products": ["dahua", "dvr", "nvr", "webserver", "sonia"],
        "severity": "CRITICAL", "cvss": 9.8, "class": "Credential Disclosure",
        "desc": "Backdoor / password-in-config disclosure lets an attacker download "
                "the credential database and log in as admin.",
        "remediation": "Upgrade to patched firmware; rotate all credentials.",
    },
    {
        "id": "CVE-2021-33044",
        "vendor": "dahua",
        "products": ["dahua", "dvr", "nvr", "ip camera"],
        "severity": "CRITICAL", "cvss": 9.8, "class": "Authentication Bypass",
        "desc": "Identity-authentication bypass during login via crafted packets — "
                "access without valid credentials.",
        "remediation": "Apply Dahua DHCC-2021 firmware; disable internet exposure.",
    },
    {
        "id": "CVE-2018-9995",
        "vendor": "dahua",
        "products": ["dvr", "nvr", "tbk", "novo", "ctring"],
        "severity": "CRITICAL", "cvss": 9.8, "class": "Authentication Bypass",
        "desc": "Cookie manipulation (Cookie: uid=admin) returns admin credentials "
                "in cleartext on many DVR clones.",
        "remediation": "Replace/patch the DVR firmware; remove from the internet.",
    },
    {
        "id": "CVE-2013-4977",
        "vendor": "foscam",
        "products": ["foscam", "ipcam client"],
        "severity": "HIGH", "cvss": 7.5, "class": "Auth / Directory Traversal",
        "desc": "Credential disclosure and traversal on legacy Foscam firmware.",
        "remediation": "Upgrade firmware; change default admin password.",
    },
    {
        "id": "CVE-2018-10088",
        "vendor": "xiongmai",
        "products": ["xiongmai", "netsurveillance", "dvr", "nvr", "xm"],
        "severity": "CRITICAL", "cvss": 9.8, "class": "Buffer Overflow / RCE",
        "desc": "Stack overflow in XiongMai uc-httpd enables unauthenticated RCE "
                "(the 'XMEye'/'Sofia' devices behind many rebranded cameras).",
        "remediation": "Device is EOL — remove from the internet / replace.",
    },
    {
        "id": "CVE-2023-44487",
        "vendor": "*",
        "products": ["nginx", "http/2", "apache"],
        "severity": "HIGH", "cvss": 7.5, "class": "HTTP/2 Rapid Reset (DoS)",
        "desc": "HTTP/2 rapid-reset denial-of-service affecting exposed web front "
                "ends (incl. camera admin panels behind nginx).",
        "remediation": "Patch the web server / reverse proxy to a fixed release.",
    },
    {
        "id": "CVE-2025-23419",
        "vendor": "*",
        "products": ["nginx", "openssl", "tls"],
        "severity": "MEDIUM", "cvss": 5.9, "class": "TLS Session Reuse",
        "desc": "Client-cert/session-reuse authentication weakness on exposed TLS "
                "endpoints.",
        "remediation": "Upgrade nginx/OpenSSL to a fixed version.",
    },
    {
        "id": "CVE-2020-25078",
        "vendor": "dlink",
        "products": ["d-link", "dcs", "alphapd"],
        "severity": "HIGH", "cvss": 7.5, "class": "Credential Disclosure",
        "desc": "Unauthenticated admin-password disclosure on D-Link DCS cameras.",
        "remediation": "Apply D-Link firmware fix; restrict remote access.",
    },
]

# Index by upper-case CVE id for O(1) lookup of Shodan-reported vulns.
CVE_BY_ID: Dict[str, Dict] = {c["id"].upper(): c for c in CVE_DB}


def cves_for_vendor(vendor: str) -> List[Dict]:
    """Return curated CVEs likely relevant to a device vendor family."""
    if not vendor:
        return []
    vendor = vendor.lower()
    return [c for c in CVE_DB if c["vendor"] == vendor or c["vendor"] == "*"]


def match_reported(vuln_ids: List[str]) -> List[Dict]:
    """Map Shodan/InternetDB-reported CVE ids to enriched KB entries."""
    out = []
    for vid in (vuln_ids or []):
        entry = CVE_BY_ID.get(str(vid).upper())
        if entry:
            out.append(entry)
        else:
            # Unknown-but-real reported CVE: keep it, mark severity unknown.
            out.append({"id": vid, "vendor": "?", "products": [],
                        "severity": "HIGH", "cvss": None,
                        "class": "Reported vulnerability",
                        "desc": "Publicly reported vulnerability on this host "
                                "(see NVD for details).",
                        "remediation": "Review NVD advisory and patch."})
    return out


def assess_risk(vendor: str, reported_vulns: List[str], ports: List[int],
                security_tier: str) -> Dict:
    """
    Produce a professional exploitability assessment for a camera.

    Combines: (a) CVEs Shodan actually reported for the host, (b) curated CVEs
    that match the fingerprinted vendor, (c) exposure factors (open tier, RTSP
    exposed, admin ports). Returns a risk level + score + finding list.
    """
    findings: List[Dict] = []
    seen = set()

    # (a) Real reported CVEs (highest confidence — Shodan observed them).
    for c in match_reported(reported_vulns):
        if c["id"] not in seen:
            findings.append({**c, "confidence": "confirmed"})
            seen.add(c["id"])

    # (b) Vendor-plausible CVEs (fingerprint-based, "potential").
    for c in cves_for_vendor(vendor):
        if c["id"] not in seen and c["vendor"] != "*":
            findings.append({**c, "confidence": "potential"})
            seen.add(c["id"])

    # Score.
    score = 0
    for f in findings:
        w = SEVERITY_WEIGHT.get(f["severity"], 30)
        score += w if f["confidence"] == "confirmed" else int(w * 0.5)

    # Exposure modifiers.
    if security_tier == "open":
        score += 60
    elif security_tier == "default_creds":
        score += 40
    if 554 in (ports or []):
        score += 15  # RTSP exposed
    if any(p in (ports or []) for p in (23, 3389)):
        score += 15  # telnet/RDP exposed

    if score >= 130:
        level = "CRITICAL"
    elif score >= 80:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk_level": level,
        "risk_score": min(score, 300),
        "cve_count": len([f for f in findings if f["confidence"] == "confirmed"]),
        "findings": findings,
    }
