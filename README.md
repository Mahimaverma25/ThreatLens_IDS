# ThreatLens

ThreatLens now runs a real live pipeline for Snort-driven detections:

`Snort -> ThreatLens agent -> ThreatLens API -> MongoDB -> rule engine + Python ML -> alerts -> Socket.io -> React dashboard`

## What Is Real Now

- `backend/agent/realtime-agent.js` is the active collector. It tails real Snort fast-alert or EVE JSON files and sends signed batches to the backend.
- `backend/api-server/routes/log.routes.js` + `controllers/log.controller.js` is the only live ingest path.
- `backend/ids-engine/app.py` exposes the Python IDS health and `/analyze` endpoint used by live ingestion.
- MongoDB `Log` documents are created before detections run.
- Node rule detections and Python ML detections both feed alerts in the live flow.
- Socket.io updates are emitted per organization, so only the right dashboard gets live events.

## What Is Demo-Only

- `POST /api/logs/simulate`
- `POST /api/alerts/scan`
- `backend/ids-engine /scan`

These are disabled by default with `ALLOW_SYNTHETIC_TRAFFIC=false` and `IDS_ENGINE_ENABLE_DEMO_SCAN=false`.

## Project Layout

```text
ThreatLens/
  backend/
    agent/        Node collector for live Snort files
    api-server/   Express API, MongoDB models, Socket.io, rule engine
    ids-engine/   Flask IDS service, IsolationForest model, training script
  frontend/       React live dashboard
```

## Prerequisites

- Node.js 18+
- Python 3.10+
- MongoDB running locally or reachable remotely
- Snort writing either:
  - fast alert output, or
  - EVE/JSON alert output

## Recommended Start Order

### 1. Backend API

```powershell
cd backend\api-server
copy .env.example .env
npm install
npm start
```

### 2. Create Agent Credentials

```powershell
cd backend\api-server
node setup-dev-keys.js
```

This creates or reuses:

- an organization
- an asset
- an API key token
- an API secret

It also syncs the agent `.env` file with the generated token and secret.

### 3. Python IDS Engine

```powershell
cd backend\ids-engine
pip install -r requirements.txt
python train_model.py
python app.py
```

Optional shared backend/IDS integration key:

`backend/api-server/.env`

```env
INTEGRATION_API_KEY=shared-secret
```

`backend/ids-engine/.env` or shell env:

```env
IDS_ENGINE_API_KEY=shared-secret
```

### 4. ThreatLens Agent

Edit `backend/agent/.env` so the Snort file paths point at the host running Snort:

```env
THREATLENS_API_URL=http://localhost:5000
THREATLENS_API_KEY=<generated-token>
THREATLENS_API_SECRET=<generated-secret>
ASSET_ID=agent-001
AGENT_MODE=snort
SNORT_FAST_LOG_PATH=C:\snort\log\alert_fast.txt
SNORT_EVE_JSON_PATH=C:\snort\log\eve.json
```

Then start it:

```powershell
cd backend\agent
npm install
npm start
```

### 5. Frontend

```powershell
cd frontend
npm install
npm start
```

## Live Flow Notes

- The agent now signs requests with an HMAC derived from the API secret and does not send the raw secret in every request.
- The backend assigns a stable `eventId` fingerprint to each log, so retries and overlapping Snort outputs do not create duplicate documents.
- The backend stores logs first, then runs:
  - local rule detections in Node
  - ML anomaly analysis in Python
- ML results are written back into `log.metadata.idsEngine`.
- New logs and alerts are emitted to organization-scoped Socket.io rooms.

## Multi-Signature Snort Testing

If your dashboard only shows one signature, Snort is usually firing the same rule repeatedly.

To generate multiple real signatures for ThreatLens, load the bundled test rules:

- [snort/threatlens-local.rules](/D:/Major%20Project/ThreatLens/snort/threatlens-local.rules)
- [snort/MULTI_SIGNATURE_TESTING.md](/D:/Major%20Project/ThreatLens/snort/MULTI_SIGNATURE_TESTING.md)

## ML Pipeline

- Training script: `backend/ids-engine/train_model.py`
- Model artifact: `backend/ids-engine/models/attack_model.pkl`
- Algorithm: `IsolationForest`
- Fallback: if the model cannot be loaded, the IDS service uses a heuristic scorer instead of failing the ingest path

Train from synthetic baseline data:

```powershell
cd backend\ids-engine
python train_model.py
```

Train from your own dataset:

```powershell
python train_model.py --input path\to\training-data.jsonl
```

Accepted input formats:

- `.json`
- `.jsonl`
- `.ndjson`
- `.csv`

## Troubleshooting

### Snort data is not reaching the dashboard

Check these in order:

1. Confirm Snort is actually writing new lines to the configured file.
2. Confirm the agent log says it is watching the correct file path.
3. Confirm the agent log shows `Submit success`.
4. Confirm MongoDB is receiving `Log` documents with `source=snort`.
5. Confirm `/api/dashboard/health` shows `snort.status=online`.

### Agent gets `401 Invalid request signature`

- Re-run `node setup-dev-keys.js`
- Make sure the backend and agent use the same token/secret pair
- Make sure the agent and backend clocks are reasonably in sync

### Snort is writing both fast alerts and EVE JSON

That is supported. ThreatLens fingerprints each normalized event so duplicate inserts from retries or mirrored outputs are suppressed.

### Python IDS looks offline

Check:

```powershell
cd backend\ids-engine
python app.py
```

Then open:

- `http://localhost:8000/health`

### Frontend does not live-update

Check:

- access token is present after login
- backend is running on the same URL the frontend expects
- Socket.io connection is not blocked by CORS
- `/api/dashboard/health` returns the organization’s live Snort status

## Useful Files

- [README.md](D:/Major%20Project/ThreatLens/README.md)
- [REALTIME_SNORT_SETUP.md](D:/Major%20Project/ThreatLens/REALTIME_SNORT_SETUP.md)
- [backend/api-server/server.js](D:/Major%20Project/ThreatLens/backend/api-server/server.js)
- [backend/agent/realtime-agent.js](D:/Major%20Project/ThreatLens/backend/agent/realtime-agent.js)
- [backend/ids-engine/train_model.py](D:/Major%20Project/ThreatLens/backend/ids-engine/train_model.py)

## Verification Commands

```powershell
cd backend\api-server
node --check server.js

cd ..\agent
node --check realtime-agent.js

cd ..\ids-engine
python train_model.py

cd ..\..\frontend
$env:BUILD_PATH='build-live-verify'
npm run build
```
