# ThreatLens API Server

This service is the live backend for ThreatLens.

## Main Responsibilities

- authenticate dashboard users with JWT + refresh cookies
- authenticate agents with API key + signed ingest requests
- store logs and alerts in MongoDB
- run the local rule engine
- call the Python IDS engine for ML analysis
- emit Socket.io updates to the correct organization room

## Important Live Route

`POST /api/logs/ingest`

This is the real ingest path used by the Snort agent.

## Start

```powershell
cd backend\api-server
copy .env.example .env
npm install
npm start
```

## Key Environment Variables

```env
MONGO_URI=mongodb://127.0.0.1:27017/threatlens
PORT=5000
JWT_SECRET=change-this
REFRESH_TOKEN_SECRET=change-this-too
IDS_ENGINE_URL=http://localhost:8000
ENABLE_IDS_ANALYSIS=true
ALLOW_SYNTHETIC_TRAFFIC=false
```

## Health

- `GET /health`
- `GET /api/dashboard/health`

The dashboard health route includes:

- database connectivity
- IDS engine status
- Snort live status for the current organization

## Troubleshooting

### Agent ingest fails with `401`

- the token or secret is wrong
- the timestamp is too far from server time
- the `ASSET_ID` does not match the API key’s asset

### Logs arrive but no alerts appear

- check MongoDB `Log` documents first
- then check whether the log source is `snort`
- then check `metadata.idsEngine` or rule-engine alert creation

### Sockets connect but pages do not update

- verify the JWT includes the correct organization
- verify the user belongs to the same organization as the ingested asset
