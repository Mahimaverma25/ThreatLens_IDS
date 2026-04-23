# ThreatLens Architecture

## Source Of Truth

ThreatLens is upgraded in place. Existing working runtime paths remain active:

- frontend: `frontend/`
- backend API: `backend/api-server/`
- live collector: `backend/agent/`
- host telemetry collector: `backend/host-agent/`
- ML engine: `backend/ids-engine/`

## Presentation-Friendly Structure

Additional folders now align the project with a cleaner HIDS + real-time monitoring architecture:

- `backend/collector/`
- `backend/ml-service/`
- `backend/queue/`
- `backend/api-server/socket/`
- `frontend/src/services/socket.js`
- `frontend/src/components/{charts,tables,map,common}/`

## Live Pipeline

```text
Snort / Suricata / Host Events
-> Collector Agent
-> /api/logs/ingest
-> Normalization + Deduplication
-> Alert Correlation + Incident Linking
-> MongoDB
-> Redis Streams / Memory Stream
-> Socket.IO
-> React Dashboard
```

## Core Services

- Socket gateway:
  - `backend/api-server/socket.js`
  - `backend/api-server/socket/index.js`
  - `backend/api-server/services/socket.service.js`
- Correlation:
  - `backend/api-server/services/alert.service.js`
  - `backend/api-server/services/incident.service.js`
  - `backend/api-server/services/correlation.service.js`
- Enrichment / ML:
  - `backend/api-server/services/detection.service.js`
  - `backend/api-server/services/enrichment.service.js`
  - `backend/ids-engine/`
  - `backend/ml-service/`
