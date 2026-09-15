/* CAMRADAR API client module */
const API = (() => {
  const base = "";

  async function _json(url, opts) {
    const res = await fetch(base + url, opts);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  return {
    meta: () => _json("/api/meta"),
    health: () => _json("/api/health"),

    scan: (body) =>
      _json("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }),

    cameras: ({ country_code, architecture, only_active, exclude_locked, require_render, limit }) => {
      const q = new URLSearchParams({
        country_code, architecture,
        only_active: only_active, exclude_locked: exclude_locked,
        require_render: require_render === undefined ? true : require_render,
        limit: limit ?? 60,
      });
      return _json(`/api/cameras?${q}`);
    },

    ping: (ids) =>
      _json("/api/ping", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ids: ids || [] }),
      }),

    probe: (ip, port) => _json(`/api/probe?ip=${encodeURIComponent(ip)}&port=${port}`),
    enrich: (ip) => _json(`/api/enrich/${encodeURIComponent(ip)}`),
    stats: (cc) => _json(`/api/stats?country_code=${cc}`),
    exposure: (cc) => _json(`/api/exposure/${cc}`),
    snapshotUrl: (url) => `/api/snapshot?url=${encodeURIComponent(url)}`,
    hlsUrl: (url) => `/api/hls?url=${encodeURIComponent(url)}`,
  };
})();
