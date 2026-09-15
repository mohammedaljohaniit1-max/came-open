/* CAMRADAR main application controller */
window.CamApp = (() => {
  let state = {
    country: "SA",
    arch: "all",
    onlyActive: true,
    excludeLocked: true,
    cameras: [],
    countries: [],
    meta: null,
  };

  const $ = (id) => document.getElementById(id);

  // ---------- Toast ----------
  function toast(msg, err = false) {
    const t = document.createElement("div");
    t.className = "toast" + (err ? " err" : "");
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 3200);
  }

  // ---------- Clock ----------
  function startClock() {
    const tick = () => {
      $("clock").textContent = new Date().toISOString().substr(11, 8);
    };
    tick();
    setInterval(tick, 1000);
  }

  // ---------- Init filters ----------
  async function loadMeta() {
    state.meta = await API.meta();
    state.countries = state.meta.countries;

    const cSel = $("filterCountry");
    cSel.innerHTML = state.meta.countries
      .map((c) => `<option value="${c.code}">${c.name}</option>`)
      .join("");
    cSel.value = "SA";

    const aSel = $("filterArch");
    aSel.innerHTML =
      `<option value="all">ALL ARCHITECTURES</option>` +
      state.meta.architectures
        .map((a) => `<option value="${a.id}">${a.label}</option>`)
        .join("");
  }

  // ---------- Data refresh ----------
  async function refresh(rescan = false) {
    const btn = $("btnScan");
    try {
      $("scanHint").textContent = rescan
        ? "Aggregating OSINT sources & running pre-flight validation…"
        : "Loading cached intelligence…";
      if (rescan) { btn.disabled = true; btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> SCANNING…`; }

      // For Gulf/SA regions, surface all discovered nodes (open + default-cred +
      // locked) so the real attack surface is visible; elsewhere require a
      // render-verified live feed so the wall never shows a dead cell.
      const gulf = ["SA", "AE", "KW"].includes(state.country);
      const payload = {
        country_code: state.country,
        architecture: state.arch,
        only_active: state.onlyActive,
        exclude_locked: state.excludeLocked,
        require_render: gulf ? false : true,
        limit: 60,
      };
      const data = rescan ? await API.scan(payload) : await API.cameras(payload);
      state.cameras = data.cameras;

      renderAll();
      $("scanHint").textContent = `${data.count} nodes matched. Last sync ${new Date().toLocaleTimeString()}.`;
      if (rescan) toast(`Pre-flight complete · ${data.count} verified nodes`);
    } catch (e) {
      toast("Scan failed: " + e.message, true);
      $("scanHint").textContent = "Error. See console.";
      console.error(e);
    } finally {
      btn.disabled = false;
      btn.innerHTML = `<i class="fa-solid fa-radar"></i> RUN SMART PRE-FLIGHT SCAN`;
    }
  }

  // ---------- Render ----------
  function renderAll() {
    const cams = state.cameras;
    // KPIs
    $("kpiTotal").textContent = cams.length;
    const alive = cams.filter((c) => c.alive).length;
    $("kpiAlive").textContent = alive;
    $("kpiRisk").textContent = cams.filter((c) => c.security_tier === "default_creds").length;
    $("kpiLocked").textContent = cams.filter((c) => c.security_tier === "locked").length;
    const lat = cams.filter((c) => c.rtt_ms != null).map((c) => c.rtt_ms);
    $("kpiLatency").textContent = lat.length
      ? Math.round(lat.reduce((a, b) => a + b, 0) / lat.length) + "ms"
      : "--";
    $("statNodes").textContent = cams.length;
    $("statAlive").textContent = alive;

    try { CamGrid.render(cams); } catch (e) { console.error("grid", e); }
    try { CamMap.render(cams, currentCenter()); } catch (e) { console.error("map", e); }
    updateRegionNote(cams);
    loadStats();
  }

  // Real Shodan exposure report for Gulf/SA regions.
  async function updateRegionNote(cams) {
    const note = $("regionNote");
    const GULF = ["SA", "AE", "KW"];
    if (!GULF.includes(state.country)) { note.hidden = true; return; }
    const name = (state.countries.find((c) => c.code === state.country) || {}).name || state.country;
    note.hidden = false;
    note.innerHTML = `<i class="fa-solid fa-satellite-dish"></i>
      <div><b>${name} — LIVE ATTACK-SURFACE REPORT (Shodan OSINT):</b>
      <span id="expLoading">querying exposed-camera intelligence…</span></div>`;
    try {
      const e = await API.exposure(state.country);
      if (e.error || !e.total) {
        const el = note.querySelector("#expLoading");
        if (el) el.textContent = "exposure data unavailable right now.";
        return;
      }
      const disc = cams.filter((c) => c.source === "Shodan OSINT Discovery");
      const open = disc.filter((c) => c.security_tier === "open").length;
      const weak = disc.filter((c) => c.security_tier === "default_creds").length;
      const locked = disc.filter((c) => c.security_tier === "locked").length;
      const prod = (e.by_product || []).slice(0, 3).map((p) => `${p.value} (${p.count})`).join(", ");
      const ports = (e.by_port || []).slice(0, 4).map((p) => `${p.value}:${p.count}`).join("  ");
      note.innerHTML = `<i class="fa-solid fa-satellite-dish"></i>
        <div>
          <b>${name} — LIVE ATTACK-SURFACE REPORT (Shodan OSINT)</b><br>
          <b style="color:#00f0ff">${e.total.toLocaleString()}</b> internet-exposed camera devices indexed ·
          top devices: ${prod || "—"}<br>
          <span style="font-family:'Share Tech Mono';font-size:11.5px">exposed ports → ${ports}</span><br>
          CAMRADAR discovered <b>${disc.length}</b> reachable nodes here →
          <span style="color:#00ff88">${open} open</span> ·
          <span style="color:#ffb800">${weak} default-cred risk</span> ·
          <span style="color:#ff3b5c">${locked} auth-locked</span>.
          ${(locked || weak) ? `Disable <b>“Exclude LOCKED”</b> to inspect protected nodes (shown as real IP + 401, never logged into).` : ""}
        </div>`;
    } catch (err) {
      const el = note.querySelector("#expLoading");
      if (el) el.textContent = "exposure query failed.";
    }
  }

  function currentCenter() {
    const c = state.countries.find((x) => x.code === state.country);
    return c ? { lat: c.lat, lon: c.lon, zoom: c.zoom } : null;
  }

  async function loadStats() {
    try {
      const stats = await API.stats(state.country);
      CamCharts.render(stats);
    } catch (e) { console.warn("stats", e); }
  }

  // ---------- Fast Ping ----------
  async function fastPing() {
    const btn = $("btnPing");
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> PINGING…`;
    try {
      const ids = state.cameras.map((c) => c.id);
      const res = await API.ping(ids);
      const byId = {};
      res.results.forEach((r) => (byId[r.id] = r));
      state.cameras.forEach((c) => {
        const r = byId[c.id];
        if (r) Object.assign(c, r);
      });
      renderAll();
      toast(`⚡ Fast ping complete · ${res.count} nodes re-probed`);
    } catch (e) {
      toast("Ping failed: " + e.message, true);
    } finally {
      btn.disabled = false;
      btn.innerHTML = `<i class="fa-solid fa-tower-broadcast"></i> ⚡ FAST PING TEST`;
    }
  }

  // ---------- Inspect modal ----------
  let inspectHls = null;
  let inspectImgTimer = null;
  function inspectPlayHls(video, srcUrl, viaProxy) {
    const url = viaProxy ? API.hlsUrl(srcUrl) : srcUrl;
    if (window.Hls && Hls.isSupported()) {
      const hls = new Hls({ maxBufferLength: 12, liveSyncDurationCount: 3 });
      inspectHls = hls;
      hls.loadSource(url);
      hls.attachMedia(video);
      hls.on(Hls.Events.MANIFEST_PARSED, () => video.play().catch(() => {}));
      hls.on(Hls.Events.ERROR, (evt, data) => {
        if (!data.fatal) return;
        hls.destroy();
        if (!viaProxy) inspectPlayHls(video, srcUrl, true);
      });
    } else if (video.canPlayType("application/vnd.apple.mpegurl")) {
      video.src = API.hlsUrl(srcUrl);
      video.play().catch(() => {});
    }
  }

  async function inspect(id) {
    const cam = state.cameras.find((c) => c.id === id);
    if (!cam) return;
    const modal = $("inspectModal");
    modal.hidden = false;

    $("inspectTitle").textContent = `${cam.city || cam.country} · ${cam.ip}:${cam.port}`;
    const tierBadge = $("inspectTier");
    tierBadge.className = "tier-badge " + cam.security_tier;
    tierBadge.textContent = cam.security_code;

    // Stream
    const streamBox = $("inspectStream");
    streamBox.innerHTML = "";
    if (cam.security_tier === "locked") {
      streamBox.innerHTML = `<div style="color:#ff3b5c;text-align:center;font-family:'Share Tech Mono'">
        <i class="fa-solid fa-lock" style="font-size:40px"></i>
        <p style="margin-top:10px">HTTP ${cam.http_status || 401} · STREAM PROTECTED</p></div>`;
    } else if (cam.stream_url && cam.stream_url.includes(".m3u8")) {
      const v = document.createElement("video");
      v.controls = true; v.autoplay = true; v.muted = true; v.playsInline = true;
      streamBox.appendChild(v);
      inspectPlayHls(v, cam.stream_url, false);
    } else if (cam.snapshot_url || cam.feed_url) {
      const feed = cam.snapshot_url || cam.feed_url;
      const img = document.createElement("img");
      img.src = API.snapshotUrl(feed) + "&t=" + Date.now();
      streamBox.appendChild(img);
      // Live-refresh the inspected MJPEG frame every 1.5s while the modal is open.
      inspectImgTimer = setInterval(() => {
        if ($("inspectModal").hidden) return;
        const fresh = new Image();
        fresh.onload = () => { img.src = fresh.src; };
        fresh.src = API.snapshotUrl(feed) + "&t=" + Date.now();
      }, 1500);
    } else if (cam.security_tier === "default_creds") {
      streamBox.innerHTML = `<div style="color:#ffb800;text-align:center;font-family:'Share Tech Mono'">
        <i class="fa-solid fa-triangle-exclamation" style="font-size:40px"></i>
        <p style="margin-top:10px">WEB UI REACHABLE · HTTP ${cam.http_status || 200}</p>
        <p style="font-size:11px;opacity:.7;margin-top:6px">Default-credential exposure candidate.<br>
        CAMRADAR does not authenticate — audit reference only.</p>
        <a href="http://${cam.ip}:${cam.port}/" target="_blank" rel="noopener"
           style="display:inline-block;margin-top:10px;color:#00f0ff;font-size:11px">
           open device UI in new tab ↗</a></div>`;
    } else {
      streamBox.innerHTML = `<div style="color:#6b8299">No renderable feed for this node.</div>`;
    }

    // Telemetry
    const shodanPorts = (cam.shodan_ports || []).join(", ");
    const shodanVulns = (cam.shodan_vulns || []);
    $("inspectTele").innerHTML = [
      ["IP / PORT", `${cam.ip}:${cam.port}`],
      ["PORT STATUS", cam.port_status],
      ["RTT LATENCY", cam.rtt_ms != null ? cam.rtt_ms + " ms" : "—"],
      ["SIGNAL", `${cam.signal_pct}% (${cam.signal_label})`],
      ["PACKET LOSS", cam.packet_loss_pct + "%"],
      ["HTTP STATUS", cam.http_status || "—"],
      ["VENDOR", cam.vendor_label],
      ["PROTOCOL", cam.protocol],
      ["ISP", cam.isp || "—"],
      ["ASN", cam.asn || "—"],
      ["OPEN PORTS", shodanPorts || "—"],
      ["KNOWN CVES", shodanVulns.length ? shodanVulns.slice(0, 4).join(", ") : "none"],
      ["SOURCE", cam.source],
      ["GEO", `${cam.city || "—"} (${cam.country_code || "—"})`],
    ].map(([k, v]) => `<div class="tele-item"><div class="k">${k}</div><div class="v">${v}</div></div>`).join("");

    // Exploitability (CVE) assessment
    const cveBox = $("inspectCve");
    const findings = cam.cve_findings || [];
    if (cam.risk_level && (findings.length || cam.risk_level !== "LOW")) {
      cveBox.hidden = false;
      const rp = $("inspectRisk");
      rp.className = "risk-pill risk-" + cam.risk_level;
      rp.textContent = `${cam.risk_level} · ${cam.risk_score}`;
      const sevColor = { CRITICAL: "#ff3b5c", HIGH: "#ff7a3c", MEDIUM: "#ffb800", LOW: "#6b8299" };
      $("inspectCveBody").innerHTML = findings.length
        ? findings.slice(0, 6).map((f) => `
            <div class="cve-item ${f.confidence}">
              <div><span class="cid">${f.id}</span>
                <span class="csev" style="background:${sevColor[f.severity] || "#6b8299"};color:#0a0a0a">${f.severity}${f.cvss ? " " + f.cvss : ""}</span>
                <span class="cve-conf">${f.confidence}</span></div>
              <div class="cmeta"><b>${f.class}</b> — ${f.desc}</div>
              <div class="cfix"><i class="fa-solid fa-wrench"></i> ${f.remediation}</div>
            </div>`).join("")
        : `<div style="color:#8aa6bd;font-size:12px">No known CVEs matched. Risk driven by exposure posture (${cam.security_code}).</div>`;
    } else {
      cveBox.hidden = true;
    }

    // Default creds reference
    const credsBox = $("inspectCreds");
    if (cam.default_creds && cam.default_creds.length) {
      credsBox.hidden = false;
      $("inspectCredsBody").innerHTML = cam.default_creds.map((c) => `<code>${c}</code>`).join("");
    } else {
      credsBox.hidden = true;
    }

    // Shodan enrichment
    const sh = $("inspectShodan");
    sh.textContent = "Querying /shodan/host/{ip} …";
    try {
      const data = await API.enrich(cam.ip);
      if (data.error) {
        sh.innerHTML = `<span style="color:#ffb800">${data.error}</span>`;
      } else {
        sh.innerHTML = [
          ["Org", data.org], ["ISP", data.isp], ["ASN", data.asn],
          ["Country", data.country_name], ["City", data.city],
          ["OS", data.os], ["Ports", (data.ports || []).join(", ")],
          ["Hostnames", (data.hostnames || []).join(", ")],
          ["Vulns", (data.vulns || []).join(", ") || "none reported"],
          ["Last update", data.last_update],
        ].filter(([, v]) => v).map(([k, v]) => `<div><b style="color:#00f0ff">${k}:</b> ${v}</div>`).join("");
      }
    } catch (e) {
      sh.innerHTML = `<span style="color:#ff3b5c">Enrichment failed.</span>`;
    }
  }

  function closeInspect() {
    $("inspectModal").hidden = true;
    if (inspectHls) { try { inspectHls.destroy(); } catch (e) {} inspectHls = null; }
    if (inspectImgTimer) { clearInterval(inspectImgTimer); inspectImgTimer = null; }
    $("inspectStream").innerHTML = "";
  }

  // ---------- Tabs ----------
  function initTabs() {
    document.querySelectorAll(".tab").forEach((t) => {
      t.onclick = () => {
        document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
        document.querySelectorAll(".tab-panel").forEach((x) => x.classList.remove("active"));
        t.classList.add("active");
        $("panel-" + t.dataset.tab).classList.add("active");
        if (t.dataset.tab === "map") CamMap.refresh();
      };
    });
  }

  // ---------- Events ----------
  function bind() {
    $("filterCountry").onchange = (e) => { state.country = e.target.value; refresh(false); };
    $("filterArch").onchange = (e) => { state.arch = e.target.value; refresh(false); };
    $("toggleActive").onchange = (e) => { state.onlyActive = e.target.checked; refresh(false); };
    $("toggleLocked").onchange = (e) => { state.excludeLocked = e.target.checked; refresh(false); };
    $("btnScan").onclick = () => refresh(true);
    $("btnPing").onclick = fastPing;
    $("inspectClose").onclick = closeInspect;
    $("openEthics").onclick = () => ($("ethicsModal").hidden = false);
    $("ethicsClose").onclick = () => ($("ethicsModal").hidden = true);
    document.querySelectorAll(".modal-overlay").forEach((o) => {
      o.addEventListener("click", (e) => { if (e.target === o) o.hidden = true; });
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { closeInspect(); $("ethicsModal").hidden = true; }
    });
  }

  async function boot() {
    startClock();
    initTabs();
    bind();
    await loadMeta();
    await refresh(false); // load cached (auto-scans on first run)
  }

  return { boot, inspect, refresh };
})();

document.addEventListener("DOMContentLoaded", () => window.CamApp.boot());
