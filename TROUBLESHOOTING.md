# ThreatLens Troubleshooting

## Agent says no Snort files found
Set `SNORT_FAST_LOG_PATH` or `SNORT_EVE_JSON_PATH` in `backend/agent/.env` to the actual Snort output file.

## Agent gets 401
Recreate API credentials with `node setup-dev-keys.js` and copy token/secret into `backend/agent/.env`.

## Dashboard shows Snort offline
Check that new Snort events are reaching MongoDB and that the most recent `source` is `snort` within the last 5 minutes.

## ML classification unavailable
Run `python scripts/train_model.py` inside `backend/ids-engine` to regenerate `models/attack_model.pkl`.
