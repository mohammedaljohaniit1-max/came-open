# 🎯 CAMRADAR — Attack Surface Intelligence Platform

> **Real-Time OSINT Camera Aggregator & Availability Validator**
> A Cybersecurity graduation project. Educational / authorized security research only.

CAMRADAR solves the single biggest weakness of traditional OSINT camera tools
(Shodan, Insecam): **stale, dead results**. Instead of dumping thousands of IPs
that went offline days ago, CAMRADAR aggregates *legitimately public* camera
feeds from government open-data sources and public broadcasts, then runs a
**Smart Pre-Flight Validator** that verifies every node is *actually live right
now* before it is rendered on the dashboard.

---

## ✨ Key Capabilities

| Feature | Description |
|---|---|
| 🛰️ **Smart Pre-Flight Validator** | Async TCP handshake with real **RTT latency**, **port status** (OPEN/FILTERED/CLOSED), **signal quality %**, **packet loss %**, and HTTP **banner grabbing** — all genuine network facts, nothing fabricated. |
| 🌍 **Multi-Source Aggregation** | NY 511 (New York State DOT, ~1,800 live HLS cams), CalTrans (California DOT, ~1,000+ cams), Austin Mobility CCTV, and a curated Saudi-first public-feed catalogue. |
| 🇸🇦 **Saudi-Arabia-First** | Default region is Saudi Arabia (Makkah, Madinah, Riyadh, Jeddah, Dammam) with real public live feeds; one-click switch to Gulf, global, and major countries. |
| 📺 **16-View Live Wall** | Simultaneous HLS video + round-robin snapshot streaming that **bypasses the browser HTTP/1.1 6-connection limit** via a server-side stream proxy. |
| 🔐 **Security Classification** | 🟢 Open Access · 🟡 Default-Creds Risk (audit reference) · 🔴 Auth-Locked (401/403 — never shows fabricated video) · ⚫ Offline. |
| 🗺️ **Geospatial Map** | Genuine **CartoDB DarkMatter** vector tiles (keyless, no CSS filters), MarkerCluster, security-coloured markers, centred on Saudi Arabia. |
| 📊 **Analytics** | Vendor distribution, most-exposed ports, security posture, protocol spread (Chart.js). |
| 🔎 **Shodan Enrichment** | Uses only the credit-free `/shodan/host/{ip}` and `/shodan/host/count` endpoints (never the paid bulk search that returns 403 on the OSS plan). |
| ⚡ **Fast Ping Test** | Re-probes all displayed nodes concurrently and updates live latency/signal badges. |

---

## 🏛️ Architecture

```
frontend/                     Dark Cyber HUD (HTML/CSS + vanilla ES6 modules)
  ├── index.html
  ├── css/styles.css
  └── js/  api.js · grid.js · map.js · charts.js · app.js
backend/
  └── app/
      ├── main.py             FastAPI app + static hosting
      ├── core/               config · knowledge base · models · SQLite (aiosqlite)
      ├── engines/validator.py   Pre-Flight Validator (TCP/RTT/banner)
      ├── services/           aggregator · scan_service · shodan_service
      └── routes/api.py       REST API + snapshot proxy + HLS proxy
app.py                        one-command launcher (port 5000)
```

**Pipeline:** `aggregate() → pre-flight validate() → classify() → persist(SQLite) → render`

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. (optional) configure your own Shodan key
cp .env.example .env      # edit SHODAN_API_KEY if desired

# 3. Run
python app.py             # → http://localhost:5000
```

Windows users can double-click **`run_camradar.bat`**.
Linux/macOS users can run **`./run_camradar.sh`**.

---

## 📡 Data Sources (all legitimately public)

| Source | Type | Notes |
|---|---|---|
| **NY 511** (`511ny.org`) | Live HLS video | New York State DOT open traffic-camera API (CORS-enabled). |
| **CalTrans** (`dot.ca.gov`) | HLS + JPEG snapshots | California DOT district CCTV status JSON. |
| **Austin Mobility** (`austinmobility.io`) | MJPEG snapshots | City of Austin open traffic CCTV. |
| **Saudi public broadcasts** | Live HLS | Makkah / Madinah public live feeds + Saudi open-data nodes. |

CAMRADAR performs **passive reachability probes and banner reads only**. It never
brute-forces, never submits credentials, and never accesses private third-party
devices. The default-credential table is a **vulnerability-signature reference**
for exposure analysis (equivalent to a CVE catalogue).

---

## ⚖️ Ethics & Legal

This platform is for **education, cyber-threat research and Attack Surface
Management**. Users must comply with the Saudi **Anti-Cyber Crime Law**
(نظام مكافحة الجرائم المعلوماتية) and all applicable local regulations.
Unauthorized access to computer systems is strictly prohibited.

---

## 🧪 Tech Stack

- **Backend:** Python 3.10+, FastAPI, httpx (async), asyncio, aiosqlite
- **Frontend:** HTML5 / CSS3, vanilla ES6 modules, Leaflet + MapLibre GL + MarkerCluster, Chart.js, hls.js, FontAwesome 6
- **Storage:** SQLite (local cache + probe history)
