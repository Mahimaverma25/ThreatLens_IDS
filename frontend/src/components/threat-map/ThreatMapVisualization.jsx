import { useEffect, useMemo, useRef } from "react";

const severityColor = {
  low: "#56d5ff",
  medium: "#ffd166",
  high: "#ff6b7d",
};

const LEAFLET_CSS_ID = "threatlens-leaflet-css";
const LEAFLET_SCRIPT_ID = "threatlens-leaflet-js";

const ensureLeafletAssets = () =>
  new Promise((resolve, reject) => {
    if (typeof window !== "undefined" && window.L) {
      resolve(window.L);
      return;
    }

    if (!document.getElementById(LEAFLET_CSS_ID)) {
      const link = document.createElement("link");
      link.id = LEAFLET_CSS_ID;
      link.rel = "stylesheet";
      link.href = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css";
      document.head.appendChild(link);
    }

    const existingScript = document.getElementById(LEAFLET_SCRIPT_ID);
    if (existingScript) {
      existingScript.addEventListener("load", () => resolve(window.L), { once: true });
      existingScript.addEventListener("error", reject, { once: true });
      return;
    }

    const script = document.createElement("script");
    script.id = LEAFLET_SCRIPT_ID;
    script.src = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js";
    script.async = true;
    script.onload = () => resolve(window.L);
    script.onerror = reject;
    document.body.appendChild(script);
  });

const buildArc = (source, target, intensity = 0.28) => {
  const midLat =
    (source.latitude + target.latitude) / 2 +
    Math.max(4, Math.abs(source.longitude - target.longitude) * intensity * 0.08);
  const midLng = (source.longitude + target.longitude) / 2;

  return [
    [source.latitude, source.longitude],
    [midLat, midLng],
    [target.latitude, target.longitude],
  ];
};

const ThreatMapVisualization = ({ attacks, highlightedAttackId, onHighlight }) => {
  const mapNodeRef = useRef(null);
  const mapRef = useRef(null);
  const layersRef = useRef([]);

  const arcs = useMemo(
    () =>
      attacks.map((attack) => ({
        ...attack,
        path: buildArc(attack.source, attack.target),
        color: severityColor[attack.severity] || severityColor.low,
      })),
    [attacks]
  );

  useEffect(() => {
    let cancelled = false;

    ensureLeafletAssets()
      .then((L) => {
        if (cancelled || !mapNodeRef.current || mapRef.current) {
          return;
        }

        const map = L.map(mapNodeRef.current, {
          center: [20, 15],
          zoom: 2,
          minZoom: 2,
          worldCopyJump: true,
          zoomControl: false,
        });

        L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
          attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
        }).addTo(map);

        mapRef.current = map;
      })
      .catch(() => {});

    return () => {
      cancelled = true;
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, []);

  useEffect(() => {
    if (!mapRef.current || !window.L) {
      return;
    }

    const L = window.L;

    layersRef.current.forEach((layer) => layer.remove());
    layersRef.current = [];

    arcs.forEach((attack) => {
      const highlighted = attack.id === highlightedAttackId;

      const polyline = L.polyline(attack.path, {
        color: attack.color,
        weight: highlighted ? 4.5 : 2.6,
        opacity: highlighted ? 0.95 : 0.58,
        smoothFactor: 1.2,
      })
        .addTo(mapRef.current)
        .bindTooltip(
          `<div class="threat-map-tooltip"><strong>${attack.attackType}</strong><span>${attack.source.country} to ${attack.target.country}</span><span>${attack.sensorType} / risk ${attack.riskScore}</span></div>`
        );

      const sourceMarker = L.circleMarker([attack.source.latitude, attack.source.longitude], {
        radius: highlighted ? 8 : 6,
        color: attack.color,
        fillColor: attack.color,
        fillOpacity: 0.85,
        weight: 1.5,
      }).addTo(mapRef.current);

      const targetMarker = L.circleMarker([attack.target.latitude, attack.target.longitude], {
        radius: highlighted ? 9 : 7,
        color: "#f8fafc",
        fillColor: attack.color,
        fillOpacity: 0.92,
        weight: highlighted ? 2.5 : 1.6,
      }).addTo(mapRef.current);

      [polyline, sourceMarker, targetMarker].forEach((layer) => {
        layer.on("mouseover", () => onHighlight?.(attack.id));
        layer.on("mouseout", () => onHighlight?.(null));
        layersRef.current.push(layer);
      });
    });
  }, [arcs, highlightedAttackId, onHighlight]);

  return (
    <div className="threat-map-canvas threat-map-leaflet-shell">
      <div className="threat-map-map-head">
        <div className="threat-map-brand-block">
          <h2>Global Attack Surface</h2>
          <p>Live telemetry routes from attacking regions to monitored assets and destinations.</p>
        </div>
        <div className="threat-map-legend">
          <span><i className="low" /> Low</span>
          <span><i className="medium" /> Medium</span>
          <span><i className="high" /> High</span>
        </div>
      </div>

      <div className="threat-map-leaflet">
        <div ref={mapNodeRef} className="threat-map-leaflet__map" />
      </div>

      <div className="threat-map-status-bar">
        <div>
          <span>Live Feed</span>
          <strong>{attacks.length} attacks tracked</strong>
        </div>
        <div>
          <span>Highest Risk</span>
          <strong>{attacks[0] ? attacks[0].riskScore : 0}</strong>
        </div>
        <div>
          <span>Latest Sensor</span>
          <strong>{attacks[0]?.sensorType || "none"}</strong>
        </div>
      </div>
    </div>
  );
};

export default ThreatMapVisualization;
