# ThreatLens Troubleshooting

## Backend does not start

- confirm `backend/api-server/.env` exists
- confirm `MONGO_URI` is reachable
- confirm the configured `PORT` is not already in use
- run `node --check backend/api-server/server.js`

## MongoDB connection fails

- start MongoDB first
- verify `MONGO_URI`
- test local default: `mongodb://127.0.0.1:27017/threatlens`

## Collector says no IDS files found

Set the right source in `backend/collector/.env`:

- `SENSOR_TYPE=host` with `HOST_EVENTS_PATH=...`
- `SENSOR_TYPE=snort` with `SNORT_FAST_LOG_PATH=...`
- `SENSOR_TYPE=suricata` with `SURICATA_EVE_JSON_PATH=...`

The Python collector now reads `backend/collector/.env` directly at startup.

## Collector gets `401 Invalid request signature`

- recreate credentials with `node setup-dev-keys.js`
- confirm `THREATLENS_API_KEY`, `THREATLENS_API_SECRET`, and `ASSET_ID`
- confirm `THREATLENS_API_URL` includes `/api`
- confirm server and collector clocks are in sync

## Dashboard shows sensor offline

- confirm new telemetry is reaching MongoDB
- confirm `/api/dashboard/health` shows recent events or heartbeats
- confirm the asset is sending `/api/agents/heartbeat`

## Collector starts but sends nothing

- for HIDS mode, append a new JSON line into the file configured by `HOST_EVENTS_PATH`
- for Snort mode, confirm `SNORT_FAST_LOG_PATH` points to the active `alert_fast.txt`
- for Suricata mode, confirm `SURICATA_EVE_JSON_PATH` points to the active `eve.json`
- use the bundled sample file in `backend/collector/sample-host-events.jsonl` for a quick local check

## Socket connection succeeds but UI stays stale

- confirm the frontend has a valid access token
- confirm backend CORS allows the frontend origin
- confirm the logged-in user belongs to the same organization as the ingested asset

## Redis is not running

- live Socket.IO still works
- stream mode falls back to in-memory buffering
- start Redis to enable durable event streaming

## ML classification unavailable

```powershell
cd backend\ids-engine
python train_model.py
python app.py
```

Then verify:

- `http://localhost:8000/health`

## Frontend build fails on Windows

- use a fresh build output path:

```powershell
$env:BUILD_PATH='build-verify'
npm run build
```

- if static asset copy fails, remove the previously locked build folder and retry
