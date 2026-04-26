# ThreatLens Agent

`backend/agent` now provides two Node-based agent entrypoints:

- `agent.js`: host-oriented HIDS agent using the shared collectors in `collectors/`
- `realtime-agent.js`: realtime Snort/IDS tail agent for network alert ingest

Both entrypoints use the same authenticated API client and current backend `v2` HMAC signing flow.

## What Changed

- shared logger moved to `utils/logger.js`
- shared API signing and transport moved to `services/apiClient.js`
- host collectors added for auth, process, file watch, system, and heartbeat payloads
- Windows Event Log collection added for auth, privilege, process, service, and PowerShell events
- local event spool added so buffered events survive temporary backend outages
- `npm start` now launches the host agent
- `npm run start:realtime` launches the Snort/realtime agent

## Setup

```bash
cd backend/agent
npm install
```

Copy `.env.example` to `.env` and fill in:

- `THREATLENS_API_URL`
- `THREATLENS_API_KEY`
- `THREATLENS_API_SECRET`
- `ASSET_ID`

Use `backend/api-server/setup-dev-keys.js` to generate matching local credentials.

## Run

Host HIDS agent:

```bash
npm start
```

Realtime Snort/IDS tail agent:

```bash
npm run start:realtime
```

## Host Agent Inputs

The host agent currently sends:

- startup auth-style activity
- periodic system telemetry
- periodic process telemetry for the running agent process
- Windows Security/System/PowerShell event telemetry when running on Windows
- file watch telemetry from `FILE_WATCH_PATHS`
- signed collector heartbeat updates to `/api/agents/heartbeat`
- local disk spool recovery for unsent events

## Realtime Agent Inputs

The realtime agent currently tails:

- `SNORT_FAST_LOG_PATH`
- `SNORT_EVE_JSON_PATH`

and forwards normalized IDS events plus signed heartbeats.

## Important Environment Variables

```env
THREATLENS_API_URL=http://localhost:5000
THREATLENS_API_KEY=your-api-token
THREATLENS_API_SECRET=your-api-secret
ASSET_ID=agent-001
FILE_WATCH_ENABLED=true
FILE_WATCH_PATHS=C:\Users\Public,C:\Windows\Temp
SYSTEM_INTERVAL_MS=15000
PROCESS_INTERVAL_MS=12000
WINDOWS_EVENT_COLLECTION_ENABLED=true
WINDOWS_EVENT_INTERVAL_MS=10000
HEARTBEAT_INTERVAL_MS=15000
SNORT_FAST_LOG_PATH=C:\snort\log\alert_fast.txt
SNORT_EVE_JSON_PATH=C:\snort\log\eve.json
BATCH_SIZE=20
MAX_RETRIES=3
SPOOL_FILE_PATH=
LOG_LEVEL=info
```

## Notes

- `THREATLENS_API_URL` may be either `http://localhost:5000` or `http://localhost:5000/api`; the client normalizes both.
- Heartbeats require the same API key, secret, and asset ID as log ingest.
- If you get `401` responses, regenerate credentials and update `.env`.
