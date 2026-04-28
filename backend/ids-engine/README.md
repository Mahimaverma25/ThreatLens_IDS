# ThreatLens IDS Engine

This Flask service provides ML anomaly analysis for live ThreatLens ingestion.

## Endpoints

- `GET /health`
- `POST /analyze`
- `GET /scan` when `IDS_ENGINE_ENABLE_DEMO_SCAN=true`

## Model

- artifact: `models/attack_model.pkl`
- algorithm: `IsolationForest`
- fallback: heuristic scorer when the model cannot be loaded

## Train

```powershell
cd backend\ids-engine
pip install -r requirements.txt
python train_model.py
```

## Run

```powershell
python app.py
```

## Optional Auth

Set `IDS_ENGINE_API_KEY` and match it with the backend `INTEGRATION_API_KEY`.

# full Folder Structure

```
ids-engine/
│
├── api/
│   └── routes.py              # API endpoints (detect, batch, health)
│
├── detector/
│   ├── pipeline.py            # Hybrid detection pipeline ⭐
│   ├── anomaly.py             # ML-based detection
│   └── rule_based.py          # Rule-based detection
│
├── models/
│   ├── train_model.py         # ML training pipeline
│   ├── load_model.py          # Model loader (RF + SVM + IF)
│   ├── attack_model.pkl       # Isolation Forest
│   ├── rf_model.pkl           # Random Forest
│   ├── svm_model.pkl          # One-Class SVM
│   └── model_metrics.json     # Model health metrics ⭐
│
├── utils/
│   ├── logger.py              # Logging system
│   ├── snort_parser.py        # Snort log parser
│   ├── feature_extractor.py   # Feature engineering ⭐
│   ├── alert_formatter.py     # Alert formatting ⭐
│   ├── stream_processor.py    # Real-time stream handling ⭐
│   └── api_client.py          # Send alerts to backend ⭐
│
├── traffic_simulator.py       # Simulated traffic generator (dev/testing)
├── config.py                  # Configuration system ⭐
├── app.py                     # Flask entry point
└── requirements.txt

```
