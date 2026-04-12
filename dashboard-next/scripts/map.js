/**
 * LLMPot Dashboard — Map Manager
 * Leaflet.js world map with attack markers and live feed
 */

"use strict";

const MapManager = (() => {
  let mainMap = null;
  let fullMap = null;
  const markerLayers = { main: null, full: null };

  // ─── Severity → color ────────────────────────────
  function sevColor(threat) {
    const map = { critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#10B981" };
    return map[threat] || "#3B82F6";
  }

  // ─── Build popup content ─────────────────────────
  function buildPopup(session) {
    const color = sevColor(session.threat);
    return `
      <div style="font-family:'Inter',sans-serif; min-width:200px;">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
          <span style="font-size:1.2rem;">${session.flag}</span>
          <strong style="font-size:0.9rem;">${session.country}</strong>
          <span style="margin-left:auto; font-size:0.65rem; background:${color}22; color:${color}; padding:2px 8px; border-radius:99px; font-weight:700; border:1px solid ${color}44;">${session.threat.toUpperCase()}</span>
        </div>
        <table style="font-size:0.78rem; width:100%; border-collapse:collapse;">
          <tr><td style="color:#64748B;padding:2px 0;">IP</td><td style="font-family:'JetBrains Mono',monospace; font-weight:600; padding:2px 0 2px 12px;">${session.ip}</td></tr>
          <tr><td style="color:#64748B;padding:2px 0;">User</td><td style="padding:2px 0 2px 12px;">${session.username}</td></tr>
          <tr><td style="color:#64748B;padding:2px 0;">Cmds</td><td style="padding:2px 0 2px 12px;">${session.commandCount}</td></tr>
          <tr><td style="color:#64748B;padding:2px 0;">Time</td><td style="padding:2px 0 2px 12px;">${window.LLMPOT_DATA.timeAgo(session.minsAgo)}</td></tr>
        </table>
      </div>
    `;
  }

  // ─── Create pulsing circle marker ───────────────
  function createAttackMarker(session) {
    const color = sevColor(session.threat);
    const size = session.threat === "critical" ? 14 : session.threat === "high" ? 12 : 10;

    const icon = L.divIcon({
      className: "",
      html: `
        <div style="position:relative;width:${size*2}px;height:${size*2}px;">
          <div style="
            position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
            width:${size*2}px;height:${size*2}px;
            border-radius:50%;background:${color}22;
            border:1px solid ${color}55;
            animation:markerPulse 2s ease-out infinite;
          "></div>
          <div style="
            position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
            width:${size}px;height:${size}px;
            border-radius:50%;background:${color};
            box-shadow:0 0 ${size}px ${color}88;
          "></div>
        </div>
      `,
      iconSize: [size * 2, size * 2],
      iconAnchor: [size, size],
    });

    return L.marker(session.coords, { icon });
  }

  // ─── Init a map ─────────────────────────────────
  function initMap(containerId, sessions, isFullScreen = false) {
    // Add keyframe CSS once
    if (!document.getElementById("mapKeyframes")) {
      const style = document.createElement("style");
      style.id = "mapKeyframes";
      style.textContent = `
        @keyframes markerPulse {
          0% { transform: translate(-50%,-50%) scale(1); opacity: 0.8; }
          100% { transform: translate(-50%,-50%) scale(2.5); opacity: 0; }
        }
      `;
      document.head.appendChild(style);
    }

    const map = L.map(containerId, {
      center: [20, 0],
      zoom: isFullScreen ? 3 : 2,
      zoomControl: !isFullScreen,
      scrollWheelZoom: isFullScreen,
      attributionControl: false,
      minZoom: 2,
    });

    // Tile layer
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 18,
    }).addTo(map);

    // Disable drag on small widget
    if (!isFullScreen) {
      map.dragging.disable();
      map.touchZoom.disable();
      map.doubleClickZoom.disable();
    }

    // Attribution
    L.control.attribution({ prefix: false }).addAttribution('© OpenStreetMap').addTo(map);

    // Marker layer
    const group = L.layerGroup().addTo(map);

    // Sample: show top 80 sessions on main, all on full
    const sample = isFullScreen ? sessions : sessions.slice(0, 80);

    sample.forEach(session => {
      if (!session.coords || session.coords[0] === 0) return;
      // Jitter coords slightly so markers in same country don't stack perfectly
      const jitteredCoords = [
        session.coords[0] + (Math.random() - 0.5) * 4,
        session.coords[1] + (Math.random() - 0.5) * 4,
      ];
      const marker = createAttackMarker({ ...session, coords: jitteredCoords });
      marker.bindPopup(buildPopup(session), { maxWidth: 260, className: "attack-popup" });
      group.addLayer(marker);
    });

    return { map, group };
  }

  // ─── Simulate live new attacks ───────────────────
  function simulateLiveMarker(mapObj, group) {
    const data = window.LLMPOT_DATA;
    const session = {
      ...data.sessions[data.randomInt(0, 50)],
      threat: data.randomFrom(["critical", "high", "medium"]),
      minsAgo: 0,
    };

    if (!session.coords || session.coords[0] === 0) return;
    const jCoords = [
      session.coords[0] + (Math.random() - 0.5) * 4,
      session.coords[1] + (Math.random() - 0.5) * 4,
    ];
    const marker = createAttackMarker({ ...session, coords: jCoords });
    marker.bindPopup(buildPopup({ ...session, minsAgo: 0 }), { maxWidth: 260, className: "attack-popup" });
    group.addLayer(marker);

    // Remove after 8 seconds to avoid clutter
    setTimeout(() => { try { group.removeLayer(marker); } catch(e) {} }, 8000);
  }

  // ─── Public API ──────────────────────────────────
  return {
    initMain() {
      if (mainMap) { mainMap.remove(); mainMap = null; }
      const container = document.getElementById("attackMap");
      if (!container) return;
      const { map, group } = initMap("attackMap", window.LLMPOT_DATA.sessions, false);
      mainMap = map;
      markerLayers.main = group;

      // Live simulation every 3s
      if (window._mainMapInterval) clearInterval(window._mainMapInterval);
      window._mainMapInterval = setInterval(() => {
        simulateLiveMarker(mainMap, markerLayers.main);
      }, 3000);
    },

    initFull() {
      if (fullMap) { fullMap.remove(); fullMap = null; }
      const container = document.getElementById("fullAttackMap");
      if (!container) return;
      // Small delay to let DOM settle
      setTimeout(() => {
        const { map, group } = initMap("fullAttackMap", window.LLMPOT_DATA.sessions, true);
        fullMap = map;
        markerLayers.full = group;
        map.invalidateSize();

        if (window._fullMapInterval) clearInterval(window._fullMapInterval);
        window._fullMapInterval = setInterval(() => {
          simulateLiveMarker(fullMap, markerLayers.full);
        }, 2000);
      }, 100);
    },

    invalidate() {
      if (mainMap) mainMap.invalidateSize();
      if (fullMap) fullMap.invalidateSize();
    },

    destroy() {
      if (window._mainMapInterval) clearInterval(window._mainMapInterval);
      if (window._fullMapInterval) clearInterval(window._fullMapInterval);
      if (mainMap) { mainMap.remove(); mainMap = null; }
      if (fullMap) { fullMap.remove(); fullMap = null; }
    },
  };
})();

window.MapManager = MapManager;
