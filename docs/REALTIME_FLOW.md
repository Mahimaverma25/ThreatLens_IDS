# ThreatLens Real-Time Flow

1. Snort writes alerts to `alert_fast.txt` and/or `eve.json`.
2. `backend/agent/realtime-agent.js` tails those files and parses every new alert.
3. The agent signs the payload with `x-api-key`, `x-api-secret`, `x-timestamp`, and `x-signature`.
4. `POST /api/logs/ingest` stores logs in MongoDB.
5. The backend enriches each log with optional ML output from the Python IDS engine.
6. Rule detection and Snort-derived alerting create/update alert documents.
7. Socket.io emits normalized `logs:new`, `alerts:new`, and `alerts:update` events.
8. The React dashboard refreshes logs, alerts, and health panels.
