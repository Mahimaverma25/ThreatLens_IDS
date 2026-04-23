# ThreatLens

ThreatLens is now being upgraded as a HIDS-plus-real-time monitoring system.

The new operating model is:

`Host telemetry + IDS events -> collector -> ThreatLens API -> MongoDB -> rule correlation -> optional IDS engine analysis -> Socket.IO -> React SOC dashboard`

## Current Direction

ThreatLens is no longer being treated as only a Snort dashboard.

Primary focus:
- host telemetry
- endpoint detection
- incident correlation
- asset heartbeat and coverage
- live socket-driven monitoring

Supporting signals:
- Snort
- Suricata
- Python IDS engine analysis

## Active Structure

```text
ThreatLens/
  backend/
    api-server/   Express API, auth, ingest, models, rules, Socket.IO
    collector/    File-based host / Snort / Suricata collector
    ids-engine/   Python analysis service
    queue/        Optional event streaming utilities
  frontend/       React dashboard
  docs/           Architecture and upgrade notes
  snort/          Local IDS testing assets
```

## What Works Now

- signed collector ingest through `/api/logs/ingest`
- collector heartbeat through `/api/agents/heartbeat`
- MongoDB log persistence
- real-time Socket.IO updates
- alert generation from rule engine
- incident tracking
- dashboard health and live updates
- host-focused detections already in backend rule logic

## HIDS Event Types Supported In Backend Rules

- `auth.login`
- `process.start`
- `file.change`
- `service.change`
- `startup.persistence`
- `privilege.escalation`

## Collector Modes

The current collector can be used in three modes:

- `SENSOR_TYPE=host`
- `SENSOR_TYPE=snort`
- `SENSOR_TYPE=suricata`

### Host Collector Example

```env
THREATLENS_API_URL=http://localhost:5000/api
THREATLENS_API_KEY=your-api-key
THREATLENS_API_SECRET=your-api-secret
ASSET_ID=host-agent-001
SENSOR_TYPE=host
HOST_EVENTS_PATH=C:\threatlens\host-events.jsonl
POLL_INTERVAL_SECONDS=5
HEARTBEAT_INTERVAL_SECONDS=15
```

Example host event JSONL line:

```json
{"timestamp":"2026-04-22T10:45:00Z","eventType":"process.start","message":"Suspicious PowerShell execution","severity":"High","hostname":"WS-101","ip":"10.0.0.25","process":{"name":"powershell.exe","pid":2440,"parentPid":1200,"commandLine":"powershell -enc ..."},"user":{"name":"student"},"elevated":true}
```

### Snort Collector Example

```env
SENSOR_TYPE=snort
SNORT_FAST_LOG_PATH=C:\snort\log\alert_fast.txt
```

### Suricata Collector Example

```env
SENSOR_TYPE=suricata
SURICATA_EVE_JSON_PATH=C:\suricata\log\eve.json
```

## Start Order

### 1. API Server

```powershell
cd backend\api-server
npm install
npm start
```

### 2. IDS Engine

```powershell
cd backend\ids-engine
python app.py
```

### 3. Collector

For host or Snort mode:

```powershell
cd backend\collector
python snort_collector.py
```

For Suricata mode:

```powershell
cd backend\collector
python suricata_collector.py
```

### 4. Frontend

```powershell
cd frontend
npm install
npm start
```

## Immediate Goal

Convert the current repo into a professional student-project architecture for:

- real-time HIDS monitoring
- host alerting and incident correlation
- asset heartbeat visibility
- supporting NIDS telemetry
- future ML enrichment without breaking the base pipeline
