# ThreatLens Real-Time Snort Setup

This guide is for the real pipeline only:

`Snort -> agent -> backend -> MongoDB -> detections -> sockets -> dashboard`

## 1. Start MongoDB

Make sure MongoDB is available before anything else.

## 2. Start The API Server

```powershell
cd backend\api-server
copy .env.example .env
npm install
npm start
```

Recommended settings:

```env
ENABLE_DEMO_TELEMETRY=false
ALLOW_SYNTHETIC_TRAFFIC=false
ENABLE_IDS_ANALYSIS=true
```

## 3. Create Or Refresh Agent Credentials

```powershell
cd backend\api-server
node setup-dev-keys.js
```

This will sync:

- `THREATLENS_API_KEY`
- `THREATLENS_API_SECRET`
- `ASSET_ID`

into `backend/agent/.env`.

## 4. Train And Start The Python IDS Engine

```powershell
cd backend\ids-engine
pip install -r requirements.txt
python train_model.py
python app.py
```

Optional shared integration key:

Backend:

```env
INTEGRATION_API_KEY=my-shared-key
```

IDS engine:

```env
IDS_ENGINE_API_KEY=my-shared-key
```

## 5. Point The Agent At Real Snort Files

Update `backend/agent/.env`:

```env
AGENT_MODE=snort
SNORT_FAST_LOG_PATH=C:\snort\log\alert_fast.txt
SNORT_EVE_JSON_PATH=C:\snort\log\eve.json
```

Only one path is required. If both are enabled, ThreatLens will suppress duplicate inserts by event fingerprint.

## 6. Start The Agent

```powershell
cd backend\agent
npm install
npm start
```

Healthy agent log signs:

- `Watching Snort fast alert file`
- `Watching Snort EVE JSON file`
- `Live Snort event buffered`
- `Submit success`

## 7. Start The Frontend

```powershell
cd frontend
npm install
npm start
```

## 8. Verify End-To-End

1. Trigger a real Snort rule hit.
2. Confirm the agent logs a buffered event and a successful submit.
3. Confirm MongoDB receives a `Log` with `source=snort`.
4. Confirm related alerts appear from:
   - `source=snort`
   - `source=rule-engine`
   - `source=ids-engine-ml` when the ML analysis flags an anomaly
5. Confirm the dashboard updates without manual refresh.

### Generate multiple signatures for the dashboard

Use the bundled multi-signature test pack:

- [snort/threatlens-local.rules](/D:/Major%20Project/ThreatLens/snort/threatlens-local.rules)
- [snort/MULTI_SIGNATURE_TESTING.md](/D:/Major%20Project/ThreatLens/snort/MULTI_SIGNATURE_TESTING.md)

This gives you several safe test alerts such as:

- ICMP activity
- HTTP admin probe
- SQL injection probe
- SSH probe
- SMB probe
- RDP probe
- DNS tunnel keyword

## 9. Fast Troubleshooting

### Backend shows `snort.status=offline`

- No fresh Snort logs were ingested in the last 5 minutes.
- Check the agent path and Snort output.

### Agent returns `401`

- Run `node setup-dev-keys.js` again.
- Make sure the agent `.env` matches the newly generated token and secret.

### IDS engine is offline

- Start `backend/ids-engine/app.py`
- Check `http://localhost:8000/health`

### Dashboard still shows old demo data

- Existing demo rows can remain in MongoDB.
- New dashboard queries now prioritize live Snort data and real alert sources.
