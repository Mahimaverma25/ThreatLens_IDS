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
