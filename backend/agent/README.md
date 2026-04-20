# ThreatLens Agent

The active agent entrypoint is `realtime-agent.js`.

It tails real Snort output files and sends signed log batches to `POST /api/logs/ingest`.

## Supported Inputs

- Snort fast alerts
- Snort EVE JSON alerts

## Required Environment Variables

```env
THREATLENS_API_URL=http://localhost:5000
THREATLENS_API_KEY=<generated-token>
THREATLENS_API_SECRET=<generated-secret>
ASSET_ID=agent-001
AGENT_MODE=snort
SNORT_FAST_LOG_PATH=C:\snort\log\alert_fast.txt
SNORT_EVE_JSON_PATH=C:\snort\log\eve.json
```

WSL/Linux example:

```env
SNORT_FAST_LOG_PATH=/var/log/snort/snort.alert.fast
SNORT_EVE_JSON_PATH=/var/log/snort/eve.json
```

## Start

```powershell
cd backend\agent
npm install
npm start
```

## Reliability Changes

- request signing no longer sends the raw secret on every request
- duplicate Snort events are suppressed downstream by event fingerprint
- failed batches are retried and restored to the in-memory buffer
- the agent caps the buffer so a dead backend does not grow memory forever

## Troubleshooting

### No Snort events appear

- verify the configured file path exists
- verify the agent user can read the file
- verify Snort is writing new lines to it
- check `agent-combined.log`

### The agent says the Snort file is not readable

- Snort may be writing logs as another user/group such as `snort:adm`
- grant your shell user read access, for example by adding it to the correct group
- or run the agent with permission to read the Snort log

### The agent says `Unauthorized`

- run `backend/api-server/setup-dev-keys.js`
- make sure the token/secret in `.env` were updated

### The backend is healthy but nothing is sent

- confirm `AGENT_MODE=snort`
- confirm the agent log shows `Watching Snort ...`
