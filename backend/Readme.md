# ThreatLens Backend

ThreatLens now runs as a hybrid IDS backend with:
- a Node.js control API for auth, ingest, incidents, rules, reports, threat intel, and sockets
- a Python IDS engine for hybrid Random Forest plus SVM analysis
- Snort-backed NIDS ingest
- host-agent HIDS ingest with heartbeat and asset health tracking

## Services

### `api-server`
- JWT auth with refresh cookies
- RBAC for `admin`, `analyst`, and `viewer`
- HMAC-signed agent ingest
- normalized event pipeline
- rule detections
- alert correlation into incidents
- live Socket.IO events

### `ids-engine`
- event feature normalization
- Random Forest classification
- SVM anomaly scoring
- legacy anomaly fallback
- model health and training metadata

### `host-agent`
- native Windows and Linux telemetry polling
- optional JSONL tail mode for lab replay
- file integrity checks on sensitive paths
- local disk buffering for resilient delivery

## Primary API Routes

### Authentication
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET /api/auth/me`

### Ingest and Monitoring
- `POST /api/logs/ingest`
- `GET /api/logs`
- `POST /api/logs/upload`
- `POST /api/agents/heartbeat`
- `GET /api/agents/heartbeats`
- `POST /api/agents/register`

### Detection and Operations
- `GET /api/alerts`
- `PATCH /api/alerts/:id`
- `GET /api/incidents`
- `GET /api/incidents/:id`
- `PATCH /api/incidents/:id`
- `GET /api/rules`
- `POST /api/rules`
- `PATCH /api/rules/:id`
- `DELETE /api/rules/:id`

### Intelligence and Reporting
- `GET /api/intel/threat-intel`
- `GET /api/intel/threat-map`
- `GET /api/intel/model-health`
- `GET /api/intel/watchlist`
- `POST /api/intel/watchlist`
- `DELETE /api/intel/watchlist/:id`
- `GET /api/reports`
- `GET /api/reports/export/alerts.csv`
- `GET /api/reports/export/logs.csv`

## Real-Time Events
- `logs:new`
- `alerts:new`
- `alerts:update`
- `incidents:new`
- `incidents:update`
- `agents:heartbeat`
- `health:update`

## Runtime Flow

1. Sensors and agents send signed events.
2. The API normalizes events into the shared schema.
3. Rule detections run immediately.
4. The Python IDS engine enriches events with RF and SVM analysis.
5. Alerts are created or updated.
6. Correlation rolls alerts into incidents.
7. Dashboard clients receive live updates over sockets.
