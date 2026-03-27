# ThreatLens IDS Engine

This is the Python-based detection engine for ThreatLens. It provides REST endpoints for health checks and network traffic scanning, and implements both rule-based and anomaly-based detection.

## Features
- REST API (Flask)
- Rule-based detection (DDoS, brute force, etc.)
- Optional anomaly detection (ML model, if present)
- Traffic simulation for testing
- Logging with configurable log level

## Folder Structure
```
ids-engine/
    app.py
    requirements.txt
    detector/
        rule_based.py
        anomaly.py
        traffic_simulator.py
    models/
    utils/
        logger.py
```

## Setup & Run

1. Create a virtual environment and install dependencies:
   ```bash
   cd backend/ids-engine
   python -m venv .venv
   .venv/Scripts/activate  # or source .venv/bin/activate on Linux/Mac
   pip install -r requirements.txt
   ```

2. (Optional) Place your ML model at `models/attack_model.pkl` for anomaly detection.

3. Start the engine:
   ```bash
   python app.py
   ```

## API Endpoints
- `GET /health` — Health check
- `GET /scan?samples=N` — Simulate and scan N traffic samples (default 1, max 50)

## Security
- No authentication by default (run behind firewall or API gateway)
- Logs all errors and warnings

## Notes
- If `joblib` or the model file is missing, anomaly detection is disabled automatically.
- Designed to be called by the Node.js backend for real-time detection.


# workflow
Snort
  │
  ▼
Agent
  │
  ▼
POST /analyze
  │
  ▼
IDS Engine (Python)
  ├ anomaly detection
  ├ rule-based detection
  └ ML model
  │
  ▼
Send result → API Server
  │
  ▼
MongoDB
  │
  ▼
React Dashboard

'''