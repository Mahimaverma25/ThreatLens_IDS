# ThreatLens API Server

This service is the live backend for ThreatLens. It keeps the existing Express/MongoDB architecture and upgrades it into a real-time security monitoring backend.

## Responsibilities

- authenticate dashboard users with JWT + refresh cookies
- authenticate collectors with API key + HMAC signatures
- receive batched telemetry on `POST /api/logs/ingest`
- normalize and store logs in MongoDB
- trigger rule-based and ML-assisted detections
- publish real-time events through Socket.IO
- publish durable stream events through Redis Streams when Redis is configured
- expose dashboard, incidents, intel, reports, and health APIs

## Active Routes

- `POST /api/logs/ingest`
- `POST /api/agents/heartbeat`
- `GET /health`
- `GET /api/dashboard/health`

## Start

```powershell
cd backend\api-server
copy .env.example .env
npm install
npm start
```

For a full local run, create collector credentials after the API starts:

```powershell
node setup-dev-keys.js
```

That syncs `THREATLENS_API_URL`, `THREATLENS_API_KEY`, `THREATLENS_API_SECRET`, and `ASSET_ID`
into `backend/collector/.env`.

## Key Environment Variables

```env
MONGO_URI=mongodb://127.0.0.1:27017/threatlens
PORT=5000
JWT_SECRET=change-this
REFRESH_TOKEN_SECRET=change-this-too
IDS_ENGINE_URL=http://localhost:8000
ENABLE_IDS_ANALYSIS=true
INTEGRATION_API_KEY=shared-secret
REDIS_URL=redis://127.0.0.1:6379
REDIS_STREAM_KEY=threatlens:events
```

## Health Checks

- `GET /health`
- `GET /api/dashboard/health`

`/api/dashboard/health` includes:

- MongoDB connection status
- IDS engine reachability and model status
- stream mode and last publish state
- recent sensor/agent heartbeat status

## Verification

```powershell
node --check server.js
node --check controllers\logs.controller.js
node --check controllers\dashboard.controller.js
```

## Troubleshooting

### Collector ingest fails with `401`

- regenerate credentials with `node setup-dev-keys.js`
- confirm `ASSET_ID` matches the API key's asset
- confirm clocks are in sync for HMAC timestamp validation

### Redis is unavailable

- the API falls back to in-memory streaming
- live Socket.IO updates still work
- durable replay/fan-out will be unavailable until Redis is reachable

### Logs arrive but no alerts appear

- confirm `Log` documents are being inserted first
- confirm `metadata.sensorType` and `source` are normalized correctly
- check `metadata.idsEngine` for ML analysis output

### Sockets connect but pages do not update

- confirm the JWT belongs to the same organization as the ingested asset
- confirm Socket.IO auth is sending the access token
- confirm `CORS_ORIGIN` matches the frontend origin
