# 🎯 CAMRADAR — Attack Surface Intelligence Platform

> **Real-Time Federated OSINT Camera Discovery & Availability Validator**
> A Cybersecurity graduation project. Educational / authorized security research only.

CAMRADAR is a professional OSINT reconnaissance platform that **discovers real,
internet-exposed IP cameras worldwide**, verifies each one is **actually live
right now**, classifies its **security posture**, and renders the open ones on a
live SOC-style dashboard — solving the #1 weakness of Shodan/Insecam: stale,
dead, unreachable results.

Every camera shown carries a **real public IP:port**, real geolocation, real
ISP/ASN, and a render-verified live frame. Nothing is faked, mocked, or padded.

---

## ✨ What makes it real

| Capability | How it's real |
|---|---|
| 🛰️ **Federated OSINT discovery** | Aggregates from **multiple** live sources: the global open-camera index (60+ countries), **Shodan** (country-filtered), and government DOT camera APIs. |
| 🔓 **Shodan without the paywall** | The OSS key can't call the paid `/host/search`. CAMRADAR uses the **free `/shodan/host/count` with `facets=ip:N`** to harvest the *real matching camera IPs* per country — credit-free — plus the keyless **Shodan InternetDB** for exact ports & CVEs. |
| 🇸🇦 **Saudi-first, and honest** | SA is the default region. The live **"KSA Attack-Surface Report"** shows the genuine exposure (≈20,000 exposed camera devices — Hikvision, Dahua, ports 554/80…) and every discovered SA node is classified **OPEN / DEFAULT-CRED-RISK / AUTH-LOCKED** with its real IP. |
| ✅ **Render verification** | Before display, CAMRADAR fetches an actual JPEG frame from each feed (validates `FFD8…FFD9` magic bytes). Only cameras that produce a **live image now** are shown. **No "no signal", no dead cells, no fakes.** |
| 📺 **16-view live wall** | Simultaneous MJPEG/JPEG + HLS via a server-side stream proxy that bypasses the browser HTTP/1.1 6-connection limit and normalises CORS / mixed-content. |
| 🔐 **Auth-tier classification** | 🟢 Open (renders) · 🟡 Default-cred exposure (web UI reachable — **flagged for audit, never logged into**) · 🔴 Auth-locked (real 401 lock screen, never faked). |
| ⚡ **Pre-flight validator** | Real async TCP handshake: measured **RTT**, port status (OPEN/FILTERED/CLOSED), signal quality %, packet loss %, HTTP banner grab & vendor fingerprint. |
| 🗺️ **Precise geo map** | Keyless **CartoDB DarkMatter** vector tiles (no CSS filters), MarkerCluster, security-coloured markers placed by real per-IP geolocation. |
| 📊 **Analytics** | Vendor distribution, most-exposed ports, security posture, protocol spread (Chart.js). |
| 🔎 **Inspect HUD** | Per-node live feed + full telemetry + real open ports, **known CVEs**, ISP/ASN, geolocation, and Shodan host enrichment. |

---

## ⚖️ Ethics & legality (read this)

CAMRADAR performs **passive reconnaissance of the already-public attack surface**:
- It reads only feeds/snapshots that a device **already exposes without
  authentication**, and metadata from public OSINT databases.
- It **never** submits credentials, **never** brute-forces, and **never**
  authenticates into third-party devices. The default-credential table is a
  **vulnerability-signature reference** (like a CVE catalogue) used to *flag*
  exposure for audit — not to log in.
- Auth-locked devices are shown as **protected (HTTP 401)** with no fabricated
  video.

Users must comply with the Saudi **Anti-Cyber Crime Law**
(نظام مكافحة الجرائم المعلوماتية) and all applicable local regulations.
Unauthorized access to computer systems is a crime.

---

## 🏛️ Architecture

```
frontend/                         Dark Cyber HUD (HTML/CSS + vanilla ES6 modules)
  ├── index.html
  ├── css/styles.css
  └── js/  api.js · grid.js · map.js · charts.js · app.js
backend/app/
  ├── main.py                     FastAPI app + static hosting
  ├── core/                       config · knowledge base · models · SQLite (aiosqlite)
  ├── engines/
  │   ├── validator.py            pre-flight TCP/RTT/banner + render verification
  │   └── osint_crawler.py        global open-camera index crawler
  ├── services/
  │   ├── aggregator.py           federates all sources → normalized nodes
  │   ├── shodan_discovery.py     credit-free Shodan facets=ip + InternetDB
  │   ├── shodan_service.py       per-IP /host/{ip} enrichment
  │   ├── geoip.py                per-IP geolocation (ip-api batch)
  │   └── scan_service.py         discover → validate → render-verify → classify
  └── routes/api.py               REST API + snapshot proxy + HLS proxy + exposure
app.py                            one-command launcher (port 5000)
run_camradar.bat / run_camradar.sh
```

**Pipeline:** `discover → geolocate → pre-flight probe → RENDER-VERIFY → classify → persist(SQLite) → render`

---

## 🚀 Quick Start

**Requirements:** Python 3.10+ (3.13 recommended), internet access. `ffmpeg`
optional (only for future RTSP transcoding).

```bash
# 1) install dependencies
pip install -r requirements.txt

# 2) (optional) configure your own Shodan key
cp .env.example .env        # edit SHODAN_API_KEY if you have your own

# 3) run
python app.py               # → http://localhost:5000
```

- **Windows:** double-click **`run_camradar.bat`**
- **Linux/macOS:** `./run_camradar.sh`

Open **http://localhost:5000**. On first load the engine auto-runs a scan
(discovery + validation) — this takes 30–120 s the first time, then results are
cached in SQLite for instant reloads. Use **RUN SMART PRE-FLIGHT SCAN** to
refresh, and **⚡ FAST PING TEST** to re-probe live latency.

### Using the dashboard
- **Target Region** — Saudi Arabia is the default; switch to Global or any country.
- **Access Filters** — “Show only ACTIVE” and “Exclude LOCKED”. *Turn Exclude
  LOCKED off* in the SA/Gulf view to inspect default-cred and auth-locked nodes.
- **Tabs** — Multi-View Wall (live feeds), Geo Map, Analytics.
- Click any camera → **Inspect HUD** (live feed + telemetry + CVEs + Shodan).

---

## 📡 Data sources (all legitimately public)

| Source | Type | Role |
|---|---|---|
| Global open-camera index | Live MJPEG/JPEG, real IP:port | Primary worldwide open cameras |
| **Shodan** `/host/count` + InternetDB | Real IPs, ports, CVEs by country | Country discovery incl. Saudi-first |
| NY 511 (NYSDOT) | Live HLS | Government traffic cameras |
| CalTrans (Caltrans) | HLS + JPEG | Government traffic cameras |
| Curated Saudi public broadcast | HLS | Makkah reference node |
| ip-api.com | Geolocation | Accurate per-IP country/city/ISP/ASN |

---

## 🔑 Configuration (`.env`)

```ini
SHODAN_API_KEY=...          # OSS key works (count+facets+InternetDB are free)
HOST=0.0.0.0
PORT=5000
PROBE_TIMEOUT_MS=1500
PROBE_CONCURRENCY=100
```

---

## 🧪 Tech stack
- **Backend:** Python 3.10+, FastAPI, httpx (async), asyncio, aiosqlite
- **Frontend:** HTML5/CSS3, vanilla ES6 modules, Leaflet + MapLibre GL + MarkerCluster, Chart.js, hls.js, FontAwesome 6
- **Storage:** SQLite (camera cache + probe history)

---

## 📌 Honest findings (for the committee)
- The global open-camera surface is large and renderable; CAMRADAR shows it live.
- **Saudi Arabia has ~20,000 internet-exposed camera devices** (Shodan), but the
  vast majority are **authenticated or RTSP-only** — genuinely open, browser-
  renderable feeds are rare there. CAMRADAR reports this truthfully: it lists the
  real discovered SA nodes and classifies each (open / default-cred / locked)
  with its real IP, instead of fabricating live feeds.
