# ThreatLens API Notes

## Auth

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET /api/auth/me`

## Ingest

- `POST /api/logs/ingest`
  - authenticated by API key + HMAC signature
  - accepts batched `logs`

## Dashboard

- `GET /api/dashboard/stats`
- `GET /api/dashboard/health`

## Alerts / Logs / Incidents

- `GET /api/alerts`
- `GET /api/logs`
- `GET /api/incidents`
- `PATCH /api/incidents/:id`

## Threat Intel / Model Health

- `GET /api/intel/threat-intel`
- `GET /api/intel/threat-map`
- `GET /api/intel/model-health`

## Agent Health

- `POST /api/agents/heartbeat`
- `GET /api/agents/heartbeats`
