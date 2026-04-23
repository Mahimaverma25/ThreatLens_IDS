# ThreatLens HIDS-First Upgrade Plan

## Source Of Truth

The existing ThreatLens repository remains the source of truth.

This upgrade does not rebuild the project from scratch. It converts the current codebase into a HIDS-plus-real-time monitoring platform by reusing the existing API server, collector, IDS engine, Socket.IO gateway, MongoDB models, auth flow, and dashboard pages.

## Fresh HIDS Direction

ThreatLens is now being treated as:

`Host telemetry collector -> API ingest -> normalization -> rule correlation -> optional ML scoring -> Socket.IO -> live SOC dashboard`

Network IDS feeds such as Snort and Suricata remain useful, but they are supporting signals. Host events become the primary telemetry layer.

## What Already Exists

### Backend

- `backend/api-server`
  - Express server
  - JWT auth and refresh flow
  - RBAC middleware
  - API-key + HMAC ingest auth
  - MongoDB models for logs, alerts, incidents, assets, users, API keys
  - dashboard, logs, alerts, incidents, assets, intel, rules, reports, users routes
  - Socket.IO integration

### Detection

- `backend/api-server/services/detector.service.js` already contains host-focused detections for:
  - suspicious process execution
  - sensitive file integrity changes
  - privilege escalation indicators
  - persistence and service modifications
  - host authentication brute force

### Collector

- `backend/collector`
  - file-based collector
  - signed ingest sender
  - heartbeat support
  - Snort and Suricata parsing

### ML

- `backend/ids-engine`
  - separate Python analysis service
  - health endpoint
  - analyze endpoint

### Frontend

- `frontend`
  - auth and protected routes
  - dashboard, logs, alerts, incidents, assets, users pages
  - live socket hook

## What Needs To Change For HIDS

### Platform Focus

- change product language from Snort-first to host-first
- treat host telemetry as first-class analytics in dashboard and health
- preserve network IDS as enrichment instead of the main story

### Collector

- support normalized host-event JSON lines
- allow host telemetry to use the same collector pipeline and signed ingest path
- keep heartbeat and retry behavior consistent for both host and IDS modes

### Backend Analytics

- include host events in live telemetry counts
- expose host telemetry health beside network IDS health
- keep correlated host incidents visible in real time

### Frontend

- show host telemetry and collector state prominently
- keep incidents and assets aligned with host monitoring

## Implementation Order

### Phase 1

- collector normalization for host events
- host telemetry through existing ingest flow
- host-aware dashboard health/stats

### Phase 2

- host-centric dashboard and incidents presentation
- clearer asset coverage for endpoint monitoring

### Phase 3

- optional ML scoring for host event classes
- richer response workflows and investigation views

## Current Progress

- real-time backbone exists
- Socket.IO live pipeline exists
- collector heartbeat exists
- network IDS ingestion exists
- host detections exist in rule engine
- current work is converting the system into a HIDS-first operating model
