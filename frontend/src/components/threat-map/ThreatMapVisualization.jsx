import { useEffect, useMemo, useState } from "react";
import { ComposableMap, Geographies, Geography, Sphere, Graticule } from "react-simple-maps";
import { geoMercator } from "d3-geo";

const GEO_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

const SEVERITY_CLASS = {
  low: "threat-map-arc-low",
  medium: "threat-map-arc-medium",
  high: "threat-map-arc-high",
};

const project = geoMercator()
  .scale(150)
  .translate([460, 255])
  .center([8, 18]);

const CONTINENT_PATHS = [
  "M115 168 C150 128 205 108 268 114 C319 118 358 136 389 156 C415 172 431 197 420 219 C404 247 356 250 327 265 C295 282 271 313 238 327 C198 343 141 335 114 301 C83 262 77 206 115 168 Z",
  "M327 323 C349 332 365 354 372 381 C378 406 377 451 362 486 C348 519 323 536 305 519 C288 501 286 465 281 434 C276 398 268 361 285 339 C295 326 310 320 327 323 Z",
  "M438 133 C488 115 545 113 604 122 C654 129 705 141 750 162 C786 179 829 205 835 233 C840 257 817 269 794 269 C763 268 745 250 719 245 C681 238 644 243 616 264 C593 281 593 313 573 327 C543 347 492 339 470 314 C449 289 458 258 453 232 C447 201 408 181 406 157 C405 145 418 138 438 133 Z",
  "M571 285 C591 275 616 278 632 291 C650 306 658 329 652 350 C647 368 628 376 611 370 C593 364 579 350 569 333 C560 317 556 297 571 285 Z",
  "M745 355 C763 345 788 346 808 356 C829 368 844 392 839 416 C834 440 808 452 784 448 C760 444 738 431 728 410 C717 388 722 365 745 355 Z",
];

const createArcPath = (source, target) => {
  const [sx, sy] = project(source.coordinates);
  const [tx, ty] = project(target.coordinates);
  const dx = tx - sx;
  const dy = ty - sy;
  const curveOffset = Math.max(40, Math.sqrt(dx * dx + dy * dy) * 0.22);
  const cx = sx + dx / 2;
  const cy = sy + dy / 2 - curveOffset;

  return {
    path: `M ${sx} ${sy} Q ${cx} ${cy} ${tx} ${ty}`,
    sourcePoint: [sx, sy],
    targetPoint: [tx, ty],
  };
};

const formatTime = (timestamp) =>
  new Date(timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

const buildTimeline = (attacks) => {
  const buckets = new Array(18).fill(0).map((_, index) => ({
    id: index,
    low: 0,
    medium: 0,
    high: 0,
  }));

  attacks.forEach((attack, index) => {
    const bucket = buckets[buckets.length - 1 - (index % buckets.length)];
    if (bucket) {
      bucket[attack.severity] += 1;
    }
  });

  return buckets;
};

const ThreatMapVisualization = ({ attacks, highlightedAttackId, onHighlight }) => {
  const [geography, setGeography] = useState(null);
  const [mapLoadFailed, setMapLoadFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;

    const loadMap = async () => {
      try {
        const response = await fetch(GEO_URL);

        if (!response.ok) {
          throw new Error("Failed to load world map");
        }

        const data = await response.json();

        if (!cancelled) {
          setGeography(data);
          setMapLoadFailed(false);
        }
      } catch (error) {
        if (!cancelled) {
          setMapLoadFailed(true);
        }
      }
    };

    loadMap();

    return () => {
      cancelled = true;
    };
  }, []);

  const attackPaths = useMemo(
    () =>
      attacks.map((attack, index) => ({
        ...attack,
        ...createArcPath(attack.source, attack.target),
        animationDelay: `${index * 0.16}s`,
      })),
    [attacks]
  );
  const timeline = useMemo(() => buildTimeline(attacks), [attacks]);

  return (
    <div className="threat-map-canvas">
      <div className="threat-map-canvas-backdrop" />
      <div className="threat-map-map-head">
        <div className="threat-map-brand-block">
          <h2>Global Attack Surface</h2>
          <p>Active telemetry flow across internet-facing assets and monitored regions.</p>
        </div>
        <div className="threat-map-legend">
          <span><i className="low" /> Low</span>
          <span><i className="medium" /> Medium</span>
          <span><i className="high" /> High</span>
        </div>
      </div>

      <svg
        className="threat-map-svg"
        viewBox="0 0 920 510"
        preserveAspectRatio="xMidYMid meet"
      >
        <defs>
          <filter id="continentGlow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="6" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        <rect x="0" y="0" width="920" height="510" rx="20" fill="rgba(3, 11, 24, 0.82)" />

        <foreignObject x="0" y="0" width="920" height="510">
          <div xmlns="http://www.w3.org/1999/xhtml" className="threat-map-geography-wrap">
            {geography && !mapLoadFailed ? (
              <ComposableMap
                projection="geoMercator"
                projectionConfig={{ scale: 145, center: [10, 18] }}
                width={920}
                height={510}
                className="threat-map-geo-svg"
              >
                <Sphere
                  stroke="rgba(84, 212, 255, 0.18)"
                  strokeWidth={0.6}
                  fill="rgba(3, 11, 24, 0.16)"
                />
                <Graticule stroke="rgba(61, 127, 170, 0.12)" strokeWidth={0.45} />
                <Geographies geography={geography}>
                  {({ geographies }) =>
                    geographies.map((geo) => (
                      <Geography
                        key={geo.rsmKey}
                        geography={geo}
                        fill="rgba(16, 38, 64, 0.92)"
                        stroke="rgba(87, 174, 233, 0.24)"
                        strokeWidth={0.48}
                        style={{
                          default: { outline: "none" },
                          hover: { fill: "rgba(24, 55, 88, 0.98)", outline: "none" },
                          pressed: { outline: "none" },
                        }}
                      />
                    ))
                  }
                </Geographies>
              </ComposableMap>
            ) : (
              <svg viewBox="0 0 920 510" className="threat-map-geo-svg" preserveAspectRatio="xMidYMid meet">
                {Array.from({ length: 12 }).map((_, index) => (
                  <line
                    key={`v-${index}`}
                    x1={index * 76}
                    y1="0"
                    x2={index * 76}
                    y2="510"
                    stroke="rgba(61, 127, 170, 0.12)"
                    strokeWidth="1"
                  />
                ))}
                {Array.from({ length: 8 }).map((_, index) => (
                  <line
                    key={`h-${index}`}
                    x1="0"
                    y1={index * 64}
                    x2="920"
                    y2={index * 64}
                    stroke="rgba(61, 127, 170, 0.12)"
                    strokeWidth="1"
                  />
                ))}

                {CONTINENT_PATHS.map((path, index) => (
                  <path
                    key={index}
                    d={path}
                    fill="rgba(15, 36, 59, 0.94)"
                    stroke="rgba(94, 173, 227, 0.30)"
                    strokeWidth="1.2"
                    filter="url(#continentGlow)"
                  />
                ))}
              </svg>
            )}
          </div>
        </foreignObject>
      </svg>

      <svg
        className="threat-map-overlay"
        viewBox="0 0 920 510"
        preserveAspectRatio="xMidYMid meet"
      >
        <defs>
          <filter id="threatMapGlow" x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="3.5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {attackPaths.map((attack) => {
          const severityClass = SEVERITY_CLASS[attack.severity] || SEVERITY_CLASS.low;
          const highlighted = attack.id === highlightedAttackId;

          return (
            <g
              key={attack.id}
              className={`threat-map-arc-group ${highlighted ? "is-highlighted" : ""}`}
              style={{ animationDelay: attack.animationDelay }}
              onMouseEnter={() => onHighlight?.(attack.id)}
              onMouseLeave={() => onHighlight?.(null)}
            >
              <path
                d={attack.path}
                className={`threat-map-arc-glow ${severityClass}`}
                filter="url(#threatMapGlow)"
              />
              <path d={attack.path} className={`threat-map-arc ${severityClass}`} />

              <circle
                cx={attack.sourcePoint[0]}
                cy={attack.sourcePoint[1]}
                r="4.6"
                className={`threat-map-node threat-map-node-source ${severityClass}`}
              />
              <circle
                cx={attack.targetPoint[0]}
                cy={attack.targetPoint[1]}
                r="5.2"
                className={`threat-map-node threat-map-node-target ${severityClass}`}
              />

              <text
                x={attack.targetPoint[0] + 8}
                y={attack.targetPoint[1] - 10}
                className="threat-map-label"
              >
                {attack.target.code}
              </text>
            </g>
          );
        })}
      </svg>

      <div className="threat-map-status-bar">
        <div>
          <span>Live Feed</span>
          <strong>{attacks.length} attacks tracked</strong>
        </div>
        <div>
          <span>Latest Event</span>
          <strong>{attacks[0] ? formatTime(attacks[0].timestamp) : "--:--:--"}</strong>
        </div>
        <div>
          <span>Latest Vector</span>
          <strong>{attacks[0]?.vector || "None"}</strong>
        </div>
      </div>

      <div className="threat-map-timeline">
        <div className="threat-map-timeline-head">
          <span>Attack Intensity Timeline</span>
          <strong>Now</strong>
        </div>
        <div className="threat-map-timeline-bars">
          {timeline.map((bucket) => (
            <div key={bucket.id} className="threat-map-timeline-bar">
              <span
                className="high"
                style={{ height: `${Math.max(bucket.high * 14, 4)}px` }}
              />
              <span
                className="medium"
                style={{ height: `${Math.max(bucket.medium * 12, 4)}px` }}
              />
              <span
                className="low"
                style={{ height: `${Math.max(bucket.low * 10, 4)}px` }}
              />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ThreatMapVisualization;
