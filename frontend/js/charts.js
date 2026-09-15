/* CAMRADAR analytics charts (Chart.js) */
const CamCharts = (() => {
  let vendor, port, tier, proto;
  const COL = {
    cyan: "#00f0ff", green: "#00ff88", amber: "#ffb800", red: "#ff3b5c",
    muted: "#6b8299", blue: "#3a7bd5", purple: "#a06bff",
  };
  const palette = [COL.cyan, COL.green, COL.amber, COL.red, COL.blue, COL.purple, COL.muted];

  Chart.defaults.color = "#8aa6bd";
  Chart.defaults.font.family = "Share Tech Mono, monospace";
  Chart.defaults.borderColor = "rgba(22,50,74,.5)";

  function tierColors(labels) {
    return labels.map((l) => {
      if (l === "open") return COL.green;
      if (l === "default_creds") return COL.amber;
      if (l === "locked") return COL.red;
      return COL.muted;
    });
  }

  function destroyAll() { [vendor, port, tier, proto].forEach((c) => c && c.destroy()); }

  function render(stats) {
    destroyAll();
    const legend = { plugins: { legend: { labels: { boxWidth: 12, font: { size: 11 } } } },
                     responsive: true, maintainAspectRatio: false };

    // Vendor doughnut
    const vLabels = Object.keys(stats.by_vendor);
    vendor = new Chart(document.getElementById("chartVendor"), {
      type: "doughnut",
      data: { labels: vLabels, datasets: [{ data: Object.values(stats.by_vendor),
        backgroundColor: palette, borderColor: "#060913", borderWidth: 2 }] },
      options: { ...legend, cutout: "60%" },
    });

    // Ports bar
    port = new Chart(document.getElementById("chartPort"), {
      type: "bar",
      data: { labels: Object.keys(stats.by_port), datasets: [{ label: "Nodes",
        data: Object.values(stats.by_port), backgroundColor: COL.cyan + "cc",
        borderColor: COL.cyan, borderWidth: 1 }] },
      options: { ...legend, plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, grid: { color: "rgba(22,50,74,.4)" } },
                  x: { grid: { display: false } } } },
    });

    // Tier doughnut
    const tLabels = Object.keys(stats.by_tier);
    tier = new Chart(document.getElementById("chartTier"), {
      type: "doughnut",
      data: { labels: tLabels.map(labelTier), datasets: [{ data: Object.values(stats.by_tier),
        backgroundColor: tierColors(tLabels), borderColor: "#060913", borderWidth: 2 }] },
      options: { ...legend, cutout: "55%" },
    });

    // Protocol polar
    proto = new Chart(document.getElementById("chartProto"), {
      type: "polarArea",
      data: { labels: Object.keys(stats.by_protocol), datasets: [{
        data: Object.values(stats.by_protocol), backgroundColor: palette.map((c) => c + "aa") }] },
      options: { ...legend, scales: { r: { grid: { color: "rgba(22,50,74,.4)" },
        ticks: { display: false } } } },
    });
  }

  function labelTier(t) {
    return { open: "Open Access", default_creds: "Default-Creds", locked: "Auth Locked", dead: "Offline" }[t] || t;
  }

  return { render };
})();
