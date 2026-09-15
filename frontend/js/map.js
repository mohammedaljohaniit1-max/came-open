/* CAMRADAR geospatial map (Leaflet + CartoDB DarkMatter + MarkerCluster) */
const CamMap = (() => {
  let map, cluster, initialized = false;

  const TIER_COLOR = {
    open: "#00ff88", default_creds: "#ffb800", locked: "#ff3b5c", dead: "#6b8299",
  };

  function init() {
    if (initialized) return;
    map = L.map("map", { zoomControl: true, attributionControl: true, maxZoom: 19, minZoom: 2 })
      .setView([24.7136, 46.6753], 6); // Saudi Arabia default

    // Keyless CartoDB DarkMatter vector tiles via MapLibre GL (no watermark,
    // no CSS colour filters — the genuine dark professional basemap).
    let usedGL = false;
    try {
      if (L.maplibreGL) {
        L.maplibreGL({
          style: "https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json",
          attribution: "&copy; OpenStreetMap &copy; CARTO",
        }).addTo(map);
        usedGL = true;
      }
    } catch (e) { console.warn("MapLibre GL unavailable, falling back", e); }

    if (!usedGL) {
      // Fallback: keyless OSM HOT dark-ish raster.
      L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
        { attribution: "&copy; OpenStreetMap &copy; CARTO", subdomains: "abcd", maxZoom: 19 }).addTo(map);
    }

    cluster = L.markerClusterGroup({ maxClusterRadius: 45 });
    map.addLayer(cluster);
    initialized = true;
  }

  function marker(cam) {
    const color = TIER_COLOR[cam.security_tier] || TIER_COLOR.dead;
    const icon = L.divIcon({
      className: "",
      html: `<div style="width:16px;height:16px;border-radius:50%;background:${color};
             border:2px solid #041018;box-shadow:0 0 10px ${color};"></div>`,
      iconSize: [16, 16], iconAnchor: [8, 8],
    });
    const m = L.marker([cam.latitude, cam.longitude], { icon });
    m.bindPopup(popupHtml(cam));
    m.on("popupopen", () => {
      const btn = document.querySelector(`#pop-${cam.id}`);
      if (btn) btn.onclick = () => window.CamApp.inspect(cam.id);
    });
    return m;
  }

  function popupHtml(cam) {
    const tierTxt = { open: "OPEN ACCESS", default_creds: "DEFAULT-CREDS RISK",
                      locked: "AUTH LOCKED", dead: "OFFLINE" }[cam.security_tier];
    return `<div class="map-pop">
      <h4>${cam.city || cam.country}</h4>
      <div class="row">IP: ${cam.ip}:${cam.port}</div>
      <div class="row">ISP: ${cam.isp || "—"}</div>
      <div class="row">Vendor: ${cam.vendor_label}</div>
      <div class="row">Status: ${tierTxt}</div>
      <div class="row">RTT: ${cam.rtt_ms != null ? cam.rtt_ms + " ms" : "—"} · Signal: ${cam.signal_pct}%</div>
      <button id="pop-${cam.id}"><i class="fa-solid fa-eye"></i> INSPECT NODE</button>
    </div>`;
  }

  function render(cameras, center) {
    init();
    cluster.clearLayers();
    const geo = cameras.filter((c) => c.latitude != null && c.longitude != null);
    geo.forEach((c) => cluster.addLayer(marker(c)));
    if (center) map.setView([center.lat, center.lon], center.zoom);
    setTimeout(() => map.invalidateSize(), 200);
  }

  function refresh() { if (map) setTimeout(() => map.invalidateSize(), 100); }

  return { render, refresh };
})();
