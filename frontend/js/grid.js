/* CAMRADAR Multi-View Wall
   Solves the browser HTTP/1.1 6-connection limit with a round-robin snapshot
   scheduler: instead of holding N persistent MJPEG connections, it refreshes a
   staggered subset of cells each tick, so all 16+ cells stay live smoothly. */
const CamGrid = (() => {
  let cameras = [];
  let timer = null;
  let cursor = 0;
  const REFRESH_MS = 1200;   // one batch every 1.2s
  const BATCH = 4;           // refresh 4 cells per tick (bypasses 6-conn limit)
  const hlsInstances = {};

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
    Object.values(hlsInstances).forEach((h) => h && h.destroy());
  }

  /* Robust HLS playback: try the direct (CORS-enabled) URL first for lowest
     latency; on a fatal network/media error, transparently retry through the
     server-side proxy (/api/hls) which normalises CORS + mixed-content. */
  function playHls(id, video, srcUrl, viaProxy = false) {
    const url = viaProxy ? API.hlsUrl(srcUrl) : srcUrl;

    if (window.Hls && Hls.isSupported()) {
      const hls = new Hls({ maxBufferLength: 10, liveSyncDurationCount: 3, enableWorker: true });
      hlsInstances[id] = hls;
      hls.loadSource(url);
      hls.attachMedia(video);
      hls.on(Hls.Events.MANIFEST_PARSED, () => video.play().catch(() => {}));
      hls.on(Hls.Events.ERROR, (evt, data) => {
        if (!data.fatal) return;
        hls.destroy();
        if (!viaProxy) {
          playHls(id, video, srcUrl, true); // fallback to proxy
        } else {
          showDead(id);
        }
      });
    } else if (video.canPlayType("application/vnd.apple.mpegurl")) {
      // Native HLS (Safari): use proxy directly to avoid CORS issues.
      video.src = API.hlsUrl(srcUrl);
      video.play().catch(() => {});
      video.addEventListener("error", () => showDead(id));
    } else {
      showDead(id);
    }
  }

  function cellHtml(cam) {
    const tier = cam.security_tier;
    const tagTxt = { open: "OPEN", default_creds: "DEFAULT", locked: "LOCKED", dead: "DEAD" }[tier] || "—";
    // A node renders live only if it's OPEN with a real feed URL (or an HLS node).
    const hasFeed = (cam.snapshot_url || cam.feed_url || cam.stream_url) && tier === "open";
    const sig = cam.signal_label || "NO SIGNAL";
    const loc = (cam.city ? cam.city + ", " : "") + (cam.country_code || "");
    let overlay = "";
    if (tier === "locked") overlay = lockedOverlay(cam);
    else if (!hasFeed && tier === "default_creds") overlay = defaultCredOverlay(cam);
    return `
      <div class="cam-cell tier-${tier}" data-id="${cam.id}" title="${cam.ip}:${cam.port}">
        <div class="cam-tag ${tier}">${tagTxt}</div>
        ${hasFeed ? `<div class="cam-live"><span class="dot"></span>LIVE</div>` : ""}
        <div class="cam-ip">${cam.ip}:${cam.port}</div>
        ${hasFeed ? `<div class="cam-loading">ACQUIRING FEED…</div>` : ""}
        <div class="cam-media" data-media></div>
        ${overlay}
        <div class="cam-meta">
          <div class="cm-name"><i class="fa-solid fa-location-dot"></i> ${loc || "Unknown"}</div>
          <div class="cm-sub">
            <span class="ping-badge">${cam.rtt_ms != null ? cam.rtt_ms + "ms" : "—"}</span>
            <span class="sig-${sig}">▮ ${cam.signal_pct}%</span>
            <span>${(cam.isp || cam.vendor_label || "").slice(0, 18)}</span>
          </div>
        </div>
      </div>`;
  }

  function defaultCredOverlay(cam) {
    return `<div class="cam-locked-overlay" style="background:repeating-linear-gradient(45deg,#1a1405,#1a1405 10px,#211a06 10px,#211a06 20px);color:#ffb800">
      <div><i class="fa-solid fa-triangle-exclamation"></i>
      <div class="code">WEB UI REACHABLE · HTTP ${cam.http_status || 200}</div>
      <div class="code" style="opacity:.8;margin-top:4px">DEFAULT-CRED EXPOSURE · ${cam.ip}:${cam.port}</div>
      <div class="code" style="opacity:.6;font-size:9px;margin-top:6px">Inspect for audit — CAMRADAR does not authenticate</div></div>
    </div>`;
  }

  function lockedOverlay(cam) {
    return `<div class="cam-locked-overlay">
      <div><i class="fa-solid fa-lock"></i>
      <div class="code">HTTP ${cam.http_status || 401} · PROTECTED STREAM</div>
      <div class="code" style="opacity:.7;margin-top:4px">${cam.ip}:${cam.port}</div></div>
    </div>`;
  }

  function mountMedia(cam) {
    const cell = document.querySelector(`.cam-cell[data-id="${cam.id}"] [data-media]`);
    if (!cell) return;
    // Only OPEN nodes stream media; locked/default-cred nodes show an overlay.
    if (cam.security_tier === "locked") return;
    if (cam.security_tier === "default_creds" && !cam.stream_url) return;

    // HLS live stream
    if (cam.stream_url && cam.stream_url.includes(".m3u8")) {
      const video = document.createElement("video");
      video.muted = true; video.autoplay = true; video.playsInline = true;
      cell.appendChild(video);
      video.addEventListener("playing", () => hideLoading(cam.id));
      video.addEventListener("loadeddata", () => hideLoading(cam.id));
      playHls(cam.id, video, cam.stream_url);
      return;
    }

    // Snapshot / MJPEG image (proxied server-side: one JPEG frame per request,
    // bypassing CORS, mixed-content and the 6-connection browser limit).
    const feed = cam.snapshot_url || cam.feed_url;
    if (feed) {
      const img = document.createElement("img");
      img.alt = cam.city || "feed";
      let retries = 0;
      const load = () => {
        const probe = new Image();
        probe.onload = () => { img.src = probe.src; hideLoading(cam.id); };
        probe.onerror = () => {
          if (retries++ < 2) setTimeout(load, 1500);  // tolerate transient stalls
          else showDead(cam.id);
        };
        probe.src = API.snapshotUrl(feed) + "&t=" + Date.now();
      };
      cell.appendChild(img);
      load();
      return;
    }

    // No renderable video/snapshot: this is an OSINT metadata node
    // (reachable host, but not a public image/HLS feed). Show it honestly.
    const l = document.querySelector(`.cam-cell[data-id="${cam.id}"] .cam-loading`);
    if (l) {
      l.innerHTML = `<div style="text-align:center">
        <i class="fa-solid fa-diagram-project" style="font-size:22px;color:#00f0ff"></i>
        <div style="margin-top:6px;color:#8aa6bd">OSINT NODE · METADATA ONLY</div>
        <div style="color:#00ff88;font-size:10px;margin-top:3px">HOST REACHABLE · NO VIDEO FEED</div>
      </div>`;
    }
  }

  function hideLoading(id) {
    const l = document.querySelector(`.cam-cell[data-id="${id}"] .cam-loading`);
    if (l) l.style.display = "none";
  }
  function showDead(id) {
    const l = document.querySelector(`.cam-cell[data-id="${id}"] .cam-loading`);
    if (l) { l.textContent = "NO SIGNAL"; l.style.color = "#ff3b5c"; }
  }

  function tick() {
    // Round-robin: refresh a small batch of snapshot/MJPEG cells each tick so
    // all 16 stay live without exhausting browser connections.
    const snapCams = cameras.filter(
      (c) => (c.snapshot_url || c.feed_url) && c.security_tier !== "locked"
    );
    if (!snapCams.length) return;
    for (let i = 0; i < BATCH; i++) {
      const cam = snapCams[cursor % snapCams.length];
      cursor++;
      const img = document.querySelector(`.cam-cell[data-id="${cam.id}"] img`);
      if (img) {
        const feed = cam.snapshot_url || cam.feed_url;
        const fresh = new Image();
        fresh.onload = () => { img.src = fresh.src; };
        fresh.src = API.snapshotUrl(feed) + "&t=" + Date.now();
      }
    }
  }

  function render(list) {
    stop();
    cameras = list.slice(0, 16); // 16-view wall
    const grid = document.getElementById("camGrid");
    const empty = document.getElementById("wallEmpty");
    if (!cameras.length) {
      grid.innerHTML = "";
      empty.hidden = false;
      return;
    }
    empty.hidden = true;
    grid.innerHTML = cameras.map(cellHtml).join("");

    cameras.forEach(mountMedia);
    cameras.forEach((cam) => {
      const cell = document.querySelector(`.cam-cell[data-id="${cam.id}"]`);
      if (cell) cell.onclick = () => window.CamApp.inspect(cam.id);
    });

    timer = setInterval(tick, REFRESH_MS);
  }

  return { render, stop };
})();
