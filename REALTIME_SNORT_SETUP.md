# ThreatLens Real-Time Collector Setup

This guide is for the current real pipeline:

`Host telemetry / Snort / Suricata -> collector -> backend -> MongoDB -> detections -> sockets -> dashboard`

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

## 3. Create Or Refresh Collector Credentials

```powershell
cd backend\api-server
node setup-dev-keys.js
```

This will sync:

- `THREATLENS_API_KEY`
- `THREATLENS_API_SECRET`
- `ASSET_ID`

into `backend/collector/.env`.

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

## 5. Configure The Collector Mode

Update `backend/collector/.env`.

### HIDS mode

```env
SENSOR_TYPE=host
HOST_EVENTS_PATH=D:\Major Project\ThreatLens\backend\collector\sample-host-events.jsonl
```

### Snort mode

```env
SENSOR_TYPE=snort
SNORT_FAST_LOG_PATH=C:\snort\log\alert_fast.txt
```

### Suricata mode

```env
SENSOR_TYPE=suricata
SURICATA_EVE_JSON_PATH=C:\suricata\log\eve.json
```

Only one mode should be active at a time.

## 6. Start The Collector

```powershell
cd backend\collector
python snort_collector.py
```

For Suricata mode:

```powershell
cd backend\collector
python suricata_collector.py
```

Healthy collector log signs:

- `[host] sent`
- `[snort] sent`
- `[suricata] sent`
- heartbeat updates visible in `/api/dashboard/health`

## 7. Start The Frontend

```powershell
cd frontend
npm install
npm start
```

## 8. Verify End-To-End

1. Trigger a host event append, a real Snort rule hit, or a Suricata alert.
2. Confirm the collector logs a successful submit.
3. Confirm MongoDB receives a `Log` with `source=host`, `source=snort`, or `source=suricata`.
4. Confirm related alerts appear from:
   - `source=snort` or `source=suricata` for direct IDS alerts
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

### Backend shows the collector or sensor offline

- No fresh telemetry or heartbeat was ingested in the last 5 minutes.
- Check the collector path and selected mode.

### Collector returns `401`

- Run `node setup-dev-keys.js` again.
- Make sure the collector `.env` matches the newly generated token and secret.

### IDS engine is offline

- Start `backend/ids-engine/app.py`
- Check `http://localhost:8000/health`

### Dashboard still shows old data

- Existing demo rows can remain in MongoDB.
- New dashboard queries now prioritize live host telemetry, IDS data, and real alert sources.
