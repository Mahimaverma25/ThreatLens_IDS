# ThreatLens Real-Time Flow

1. Snort and/or Suricata writes alerts to fast-alert or `eve.json` outputs.
2. `backend/agent/realtime-agent.js` tails those files and normalizes each event.
3. The collector signs every batch with API key + HMAC headers.
4. `POST /api/logs/ingest` validates the batch and stores logs in MongoDB.
5. The backend runs:
   - normalization
   - deduplication
   - rule evaluation
   - ML enrichment through `backend/ids-engine`
6. New telemetry batches publish to:
   - Socket.IO organization rooms for live UI updates
   - Redis Streams when `REDIS_URL` is configured
7. Alerts, incidents, dashboard counters, agent heartbeats, and health states are updated.
8. The React frontend receives:
   - `logs:new`
   - `alerts:new`
   - `dashboard:update`
   - `agents:heartbeat`
   - `health:update`
   - `stream:event`
