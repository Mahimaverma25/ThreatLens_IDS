# ThreatLens — Complete Project Audit & Upgrade Plan

---

## Phase 1 — Current Project Audit

### Architecture Summary

```
ThreatLens/
  backend/
    agent/           # Node.js Snort log collector (NIDS agent)
    api-server/      # Express API + MongoDB + Socket.IO + Rule engine
    ids-engine/      # Flask ML service (IsolationForest / RandomForest)
  frontend/          # React SPA (CRA) — dashboard, alerts, logs, etc.
  snort/             # Custom Snort rules for testing
```

| Layer | Tech | Status |
|-------|------|--------|
| Frontend | React 18 (CRA) | ✅ Working |
| Backend API | Express + MongoDB + Socket.IO | ✅ Working |
| ML Service | Flask + scikit-learn | ✅ Working |
| Agent | Node.js file-tail Snort collector | ✅ Working |
| Database | MongoDB (Mongoose ODM) | ✅ Working |
| Auth | JWT + refresh tokens + bcrypt | ✅ Working |

### What Is Real & Functional

| Feature | Status | Details |
|---------|--------|---------|
| Snort log ingestion | ✅ Real | Agent tails `alert_fast.txt` / `eve.json`, parses, batches, submits via HMAC-signed API |
| Event normalization | ✅ Real | `normalizeLogEntry()` + SHA-256 fingerprinting for dedup |
| Rule-based detection (Node) | ✅ Real | 17 detection rules in `detector.service.js` — brute force, SQLi, XSS, RCE, port scan, DoS, data exfil, DNS tunneling, malware beaconing, etc. |
| Rule-based detection (Python) | ✅ Real | `rule_based.py` — DDoS, brute force SSH, port scan, credential stuffing, DNS amp, data exfil, SMB lateral, sensitive service |
| ML anomaly detection | ✅ Real | IsolationForest with fallback heuristic scorer |
| ML supervised classification | ✅ Real | RandomForestClassifier trained on synthetic labeled data |
| Training pipeline | ✅ Real | `train_model.py` — synthetic data generation, supports CSV/JSON/JSONL input, outputs `.pkl` |
| Alert correlation | ✅ Real | `upsertCorrelatedAlert()` — time-window dedup, metadata merging, related-log linking |
| Socket.IO real-time | ✅ Real | Org-scoped rooms, JWT-authenticated, emits `logs:new`, `alerts:new`, `dashboard:update` |
| JWT auth + refresh tokens | ✅ Real | Access + refresh flow, httpOnly cookies, rotation, revocation |
| RBAC | ⚠️ Partial | Only `admin` / `viewer` roles exist — no `analyst` role in backend |
| HMAC agent auth | ✅ Real | v2 signature scheme with timestamp tolerance, API key model |
| Multi-tenant isolation | ✅ Real | `_org_id` on every model, `orgIsolation` middleware |
| Audit logging | ✅ Real | `AuditLog` model, login success/failure tracked |
| Rate limiting | ✅ Real | Express rate-limit on API and auth routes |
| Dashboard stats | ✅ Real | 24h timeline, protocol/port/IP distributions, severity breakdown |
| Health monitoring | ✅ Real | `/health` + `/api/dashboard/health` — DB, IDS engine, Snort liveness |
| Asset management | ✅ Real | CRUD + agent heartbeat updating `agent_last_seen` |
| Report export | ✅ Real | CSV export for alerts and logs |
| File upload ingestion | ✅ Real | JSON/CSV file upload → normalize → detect |

### What Is Demo / Simulated Only

| Feature | Status |
|---------|--------|
| `POST /api/logs/simulate` | 🔶 Demo — disabled by default (`ALLOW_SYNTHETIC_TRAFFIC=false`) |
| `POST /api/alerts/scan` | 🔶 Demo — disabled by default |
| `GET /scan` (IDS engine) | 🔶 Demo — disabled by default |
| `traffic_simulator.py` | 🔶 Demo — generates random traffic samples |
| Training data | 🔶 Synthetic — `generate_benign_sample()` / `generate_attack_sample()` |

### What Is Missing Entirely

| Feature | Status |
|---------|--------|
| **HIDS agent** | ❌ Not implemented — no host monitoring at all |
| **SVM model** | ❌ Not implemented — only RF + IsolationForest exist |
| **Incident model/API** | ❌ No `Incident` model — `_incident_id` in Alert schema is unused |
| **Analyst role** | ❌ Backend only has admin/viewer |
| **Threat Intel integration** | ❌ Frontend page exists but no backend |
| **Response Playbooks** | ❌ Frontend page exists but no backend |
| **Threat Map** | ⚠️ Frontend exists but uses static/mock data |
| **Search/filtering on alerts** | ⚠️ Basic — no full-text search |
| **Agent heartbeat API** | ⚠️ Implicit via ingest — no dedicated endpoint |
| **Model evaluation metrics display** | ⚠️ Training outputs metrics but dashboard doesn't show them |
| **Confusion matrix / F1 in UI** | ❌ Not displayed |
| **Environment-based config** | ⚠️ Partial — `.env` files exist but secrets are hardcoded defaults |

### Frontend Pages Audit

| Page | Backend Support | Real Data |
|------|----------------|-----------|
| Dashboard | ✅ Full | ✅ Yes |
| Alerts | ✅ Full | ✅ Yes |
| AlertDetails | ✅ Full | ✅ Yes |
| Logs | ✅ Full | ✅ Yes |
| Assets | ✅ Full | ✅ Yes |
| Reports | ✅ Full | ✅ Yes |
| AccessManagement | ✅ Full | ✅ Yes |
| ModelHealth | ⚠️ Partial | ⚠️ Shows IDS health, no metrics |
| Incidents | ❌ No backend | ❌ Static/empty |
| Rules | ❌ No backend | ❌ Static/empty |
| ThreatIntel | ❌ No backend | ❌ Static/empty |
| ThreatMap | ❌ No backend | ❌ Mock data |
| ResponsePlaybooks | ❌ No backend | ❌ Static/empty |

### Strongest Parts

1. **Live Snort pipeline** — Real end-to-end: Snort → Agent → API → Detect → Alert → Socket → Dashboard
2. **Detection engine** — 17+ rule-based detectors + ML anomaly scoring running on every ingested event
3. **Security posture** — HMAC signatures, JWT refresh rotation, multi-tenant isolation, rate limiting, audit logs
4. **Event normalization** — Robust fingerprinting prevents duplicates across retries and overlapping outputs
5. **Alert correlation** — Time-window based upsert with metadata merging

### Biggest Limitations

1. **No HIDS** — The project is NIDS-only; no host-based monitoring exists
2. **No SVM** — Only IsolationForest + RandomForest; your requirement for SVM is unmet
3. **Only 2 RBAC roles** — Missing the `analyst` role
4. **Incidents module is a shell** — Schema references exist but no logic
5. **ML trained on synthetic data only** — No real dataset integration (e.g., NSL-KDD, CICIDS)
6. **Frontend pages with no backend** — Rules, ThreatIntel, Playbooks, ThreatMap are UI-only

---

## Phase 2 — Gap Analysis

### ✅ Existing (Keep & Strengthen)

- Express + MongoDB + Socket.IO backend
- JWT + refresh token auth
- Snort agent with fast-alert + EVE JSON parsing
- Rule-based detection engine (Node + Python)
- ML pipeline with RandomForest + IsolationForest
- Alert correlation with time-window dedup
- Multi-tenant org isolation
- HMAC-signed agent ingestion
- Dashboard with real-time stats
- Asset management with agent heartbeat
- Audit logging
- CSV export

### ❌ Missing (Must Build)

| Gap | Priority | Effort |
|-----|----------|--------|
| HIDS agent (Windows + Linux) | 🔴 High | Large |
| SVM anomaly detector | 🔴 High | Medium |
| Incident model + API + correlation | 🔴 High | Medium |
| `analyst` RBAC role | 🟡 Medium | Small |
| Rules CRUD API | 🟡 Medium | Medium |
| Agent heartbeat dedicated endpoint | 🟡 Medium | Small |
| Model evaluation metrics in dashboard | 🟡 Medium | Small |
| Real dataset training (NSL-KDD/CICIDS) | 🟡 Medium | Medium |
| Threat Map with real geo-IP | 🟡 Medium | Medium |
| Threat Intel feed integration | 🟠 Lower | Large |
| Response Playbooks backend | 🟠 Lower | Medium |
| WebSocket reconnect buffering | 🟡 Medium | Small |

### 🔶 Upgrade Opportunities (Quick Wins)

| Item | Effort |
|------|--------|
| Add `analyst` role to `roles.js` + User model | 1 hour |
| Add confusion matrix + F1 to ModelHealth page | 2 hours |
| Add dedicated `/api/agents/heartbeat` endpoint | 2 hours |
| Display training metrics from model artifact | 2 hours |
| Add socket reconnect with event buffering | 3 hours |
| Persist detection rules in DB (Rules CRUD) | 4 hours |
| Add Incident model + basic CRUD | 4 hours |

---

## Phase 3 — Upgrade Architecture Design

### Target Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    React Dashboard                       │
│  Dashboard │ Alerts │ Incidents │ Logs │ Assets │ ...    │
│                 Socket.IO ↕ REST API                     │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│              Express API Server (Node.js)                │
│  Auth │ RBAC │ Ingest │ Rules │ Incidents │ Reports      │
│  Detection Engine │ Alert Correlation │ Socket.IO        │
└────┬────────────────┬───────────────────┬───────────────┘
     │                │                   │
┌────▼────┐    ┌──────▼──────┐    ┌───────▼───────┐
│ MongoDB │    │ Flask ML    │    │ Redis (opt.)  │
│ Logs    │    │ RF + SVM +  │    │ Event queue   │
│ Alerts  │    │ IsoForest   │    │ Rate limiting │
│ Events  │    │ /analyze    │    └───────────────┘
│ Incidents│   │ /health     │
└─────────┘    └─────────────┘
                       ▲
     ┌─────────────────┼─────────────────┐
     │                 │                 │
┌────▼─────┐    ┌──────▼──────┐   ┌──────▼──────┐
│ NIDS     │    │ HIDS Agent  │   │ HIDS Agent  │
│ Agent    │    │ (Windows)   │   │ (Linux)     │
│ Snort    │    │ Python svc  │   │ Python svc  │
│ tail+parse│   │ EventLog    │   │ syslog      │
│ → ingest │    │ files/procs │   │ files/procs │
└──────────┘    └─────────────┘   └─────────────┘
```

### What Remains As-Is
- Express API server structure
- MongoDB models (Log, Alert, Asset, User, Organization, APIKey, AuditLog)
- Socket.IO real-time system
- JWT + refresh token auth
- NIDS agent (Snort collector)
- React frontend structure

### What Gets Extended
- `roles.js` → add `analyst` role
- `detector.service.js` → add HIDS event evaluation rules
- `detection.service.js` → add SVM model path
- `train_model.py` → add SVM training + real dataset support
- `anomaly.py` → add SVM inference alongside IsolationForest
- Dashboard page → add HIDS panels, agent health grid
- ModelHealth page → show precision/recall/F1/confusion matrix

### What Gets Added New
- `backend/hids-agent/` — Python HIDS agent service
- `Incident` model + controller + routes
- `Rule` model + controller + routes (persist detection rules in DB)
- `/api/agents/heartbeat` endpoint
- SVM detector module in `ids-engine`
- Real dataset loader (NSL-KDD / CICIDS2017)

### NIDS + HIDS Integration

Both agents submit events through the **same ingest pipeline**:

```
Agent → POST /api/logs/ingest (HMAC signed)
  → normalizeLogEntry()
  → persistLogs()
  → evaluateLog() [rule engine]
  → analyzeLogs() [ML engine]
  → emit Socket.IO events
```

HIDS events use different `source` and `eventType` values:
- `source: "hids"`, `eventType: "auth.failure"`, `"file.change"`, `"process.suspicious"`, etc.

### ML Model Integration

| Model | Role | Training Data |
|-------|------|---------------|
| RandomForest | Multiclass attack classification | Labeled dataset (synthetic + NSL-KDD) |
| SVM (RBF kernel) | Binary anomaly detection | Same feature set, one-class or binary |
| IsolationForest | Unsupervised anomaly fallback | When no labels available |

### Recommended Format: **Web-based platform** (current approach is correct)

---

## Phase 4 — Module Breakdown

### 1. NIDS Agent (`backend/agent/`)
- **Purpose**: Collect Snort alerts in real-time
- **Inputs**: Snort `alert_fast.txt`, `eve.json`
- **Outputs**: Normalized log batches → API ingest
- **Tech**: Node.js, `tail`, axios, HMAC
- **Interactions**: → API Server ingest endpoint

### 2. HIDS Agent (`backend/hids-agent/` — NEW)
- **Purpose**: Monitor host-level security events
- **Inputs**: OS event logs, file system, process list, service list
- **Outputs**: Normalized HIDS events → API ingest
- **Tech**: Python, `watchdog`, `psutil`, `pywin32`/`systemd-journal`
- **Interactions**: → API Server ingest endpoint

### 3. API Server (`backend/api-server/`)
- **Purpose**: Central REST API, detection engine, alert correlation
- **Inputs**: Agent events, user requests, ML results
- **Outputs**: Alerts, incidents, dashboard stats, Socket.IO events
- **Tech**: Express, MongoDB, Socket.IO, JWT
- **Interactions**: ↔ Agents, ↔ Frontend, → ML Service

### 4. ML Service (`backend/ids-engine/`)
- **Purpose**: ML-based anomaly/attack detection
- **Inputs**: Normalized event features from API
- **Outputs**: Anomaly scores, classifications, severity
- **Tech**: Flask, scikit-learn, joblib
- **Interactions**: ← API Server `/analyze` calls

### 5. Frontend (`frontend/`)
- **Purpose**: Real-time security monitoring dashboard
- **Inputs**: REST API responses, Socket.IO events
- **Outputs**: Visual dashboards, alert management UI
- **Tech**: React, Chart.js, Recharts, Socket.IO client
- **Interactions**: ↔ API Server

### 6. Detection Engine (inside API Server)
- **Purpose**: Rule-based + ML detection on every event
- **Inputs**: Normalized log entries
- **Outputs**: Alert creation/correlation
- **Modules**: `detector.service.js` (rules), `detection.service.js` (ML bridge)

### 7. Incident Module (NEW)
- **Purpose**: Group correlated alerts into incidents
- **Inputs**: Alerts with matching IP/type/timewindow
- **Outputs**: Incident records, status tracking
- **DB Model**: `Incident` (status, severity, linked alerts, assignee, timeline)

---

## Phase 5 — Technology Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Frontend | **React 18** (keep CRA) | Already built, works well |
| Styling | **Vanilla CSS** (current) | Already in use |
| Charts | **Recharts + Chart.js** | Already integrated |
| Backend | **Express.js** | Already built, production-grade |
| Database | **MongoDB** (Mongoose) | Already used, good for flexible event schemas |
| Real-time | **Socket.IO** | Already integrated with JWT auth |
| ML Service | **Flask + scikit-learn** | Already built, add SVM |
| NIDS Agent | **Node.js** | Already built, handles Snort well |
| HIDS Agent | **Python** | Best OS-level access (`psutil`, `watchdog`, `pywin32`) |
| Auth | **JWT + bcrypt + refresh tokens** | Already implemented |
| Queue (optional) | **Redis** or in-memory buffer | For reliable event buffering under load |
| Deployment | **Docker Compose** | Orchestrate all services cleanly |

---

## Phase 6 — Implementation Roadmap

### Sprint 1: Foundation Fixes (Week 1)
1. Add `analyst` role to backend RBAC (`roles.js`, `User.js`)
2. Create `Incident` model + basic CRUD API
3. Add dedicated `/api/agents/heartbeat` endpoint
4. Add socket reconnect buffering in frontend `useSocket.js`
5. Fix frontend pages that reference non-existent backend (Rules, ThreatIntel, Playbooks)

### Sprint 2: HIDS Agent (Week 2)
6. Create `backend/hids-agent/` Python service
7. Implement login monitoring (Windows EventLog / Linux auth.log)
8. Implement file integrity monitoring (`watchdog`)
9. Implement suspicious process detection (`psutil`)
10. Connect HIDS agent to existing ingest pipeline with HMAC auth

### Sprint 3: ML Pipeline Upgrade (Week 3)
11. Add SVM (SVC with RBF kernel) to `train_model.py`
12. Add real dataset loader (NSL-KDD CSV)
13. Add ensemble scoring: RF classification + SVM anomaly
14. Add evaluation metrics output (confusion matrix, per-class F1)
15. Display metrics in ModelHealth frontend page

### Sprint 4: Detection & Correlation (Week 4)
16. Add HIDS-specific detection rules to `detector.service.js`
17. Implement incident auto-creation from correlated alerts
18. Add severity/risk score calculation with asset criticality weighting
19. Add alert → incident linking workflow

### Sprint 5: Dashboard & UI Polish (Week 5)
20. Add HIDS event panels to Dashboard
21. Add Agent Health grid (all agents, heartbeat status)
22. Implement Rules CRUD page (backed by DB)
23. Add Threat Map with real geo-IP lookup (MaxMind GeoLite2)
24. Add incident management UI (timeline, assign, resolve)

### Sprint 6: Testing & Docs (Week 6)
25. Add API integration tests (Jest/Supertest)
26. Add ML model unit tests (pytest)
27. Add HIDS agent tests
28. Write deployment guide (Docker Compose)
29. Write API documentation

---

## Phase 7 — Code Implementation Plan

### New Files to Create

```
backend/
  hids-agent/
    agent.py              # Main HIDS agent entry point
    config.py             # Agent configuration
    collectors/
      auth_monitor.py     # Login success/failure monitoring
      file_monitor.py     # File integrity monitoring (watchdog)
      process_monitor.py  # Suspicious process detection (psutil)
      service_monitor.py  # Service/startup persistence monitoring
    api_client.py         # HMAC-signed API submission
    requirements.txt
    .env.example

  api-server/
    models/
      Incident.js         # NEW — Incident model
      Rule.js             # NEW — Persisted detection rules
    controllers/
      incident.controller.js  # NEW
      rule.controller.js      # NEW
      agent.controller.js     # NEW — heartbeat endpoint
    routes/
      incident.routes.js      # NEW
      rule.routes.js           # NEW
      agent.routes.js          # NEW

  ids-engine/
    detector/
      svm_detector.py     # NEW — SVM anomaly detector
    data/
      nsl_kdd_loader.py   # NEW — Real dataset loader
```

### Files to Modify

```
backend/api-server/
  utils/roles.js              # Add ROLE_ANALYST
  models/User.js              # Add analyst to enum
  server.js                   # Mount new routes
  services/detector.service.js  # Add HIDS detection rules
  services/detection.service.js # Add SVM model path

backend/ids-engine/
  scripts/train_model.py      # Add SVM training
  detector/anomaly.py         # Add SVM inference
  api/routes.py               # Add /model-metrics endpoint
  config.py                   # Add SVM model path

frontend/src/
  hooks/useSocket.js          # Add reconnect buffering
  pages/ModelHealth.jsx       # Show F1, confusion matrix
  pages/Incidents.jsx         # Connect to real API
  pages/Rules.jsx             # Connect to real API
  pages/ThreatMap.jsx         # Real geo-IP data
  App.js                      # Update role guards
```

### New API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/incidents` | List incidents |
| GET | `/api/incidents/:id` | Get incident detail |
| PATCH | `/api/incidents/:id` | Update incident status |
| POST | `/api/incidents/:id/assign` | Assign analyst |
| GET | `/api/rules` | List detection rules |
| POST | `/api/rules` | Create custom rule |
| PATCH | `/api/rules/:id` | Update rule |
| DELETE | `/api/rules/:id` | Delete rule |
| POST | `/api/agents/heartbeat` | Agent heartbeat |
| GET | `/api/agents` | List registered agents |
| GET | `/api/model/metrics` | Get training metrics |

### New DB Models

**Incident**
```javascript
{
  _org_id, title, description, severity, status,
  assignee, alerts: [AlertRef], timeline: [{action, by, at}],
  created_at, updated_at, resolved_at
}
```

**Rule**
```javascript
{
  _org_id, name, description, enabled, severity,
  conditions: { field, operator, value },
  action: "alert" | "block" | "log",
  created_by, created_at, updated_at
}
```

### Socket Events (existing + new)

| Event | Direction | Purpose |
|-------|-----------|---------|
| `logs:new` | Server→Client | New logs ingested |
| `alerts:new` | Server→Client | New alert created |
| `alerts:update` | Server→Client | Alert status changed |
| `dashboard:update` | Server→Client | Dashboard data refresh |
| `incidents:new` | Server→Client | **NEW** — Incident created |
| `incidents:update` | Server→Client | **NEW** — Incident updated |
| `agents:heartbeat` | Server→Client | **NEW** — Agent status change |

---

## Phase 8 — Development Prompts

### Master Implementation Prompt

> Build a hybrid IDS platform called ThreatLens with: Express.js API server (MongoDB, Socket.IO, JWT auth with refresh tokens, RBAC with admin/analyst/viewer roles), Flask ML service (RandomForest for multiclass classification, SVM for anomaly detection, IsolationForest as fallback), Node.js NIDS agent (Snort fast-alert and EVE JSON tail + parse + HMAC-signed ingest), Python HIDS agent (login monitoring, file integrity, process detection, service monitoring), React dashboard with real-time Socket.IO updates. The detection flow is: agents collect → API normalizes → rule engine evaluates → ML service scores → alerts are correlated → incidents are created → dashboard updates in real-time.

### Module-Specific Prompts

**1. HIDS Agent**
> Create a Python HIDS agent for ThreatLens that monitors: (a) login success/failure via Windows EventLog or Linux auth.log, (b) file integrity changes in configured directories using watchdog, (c) suspicious process creation using psutil, (d) service/startup changes. The agent should normalize events into the same schema as the NIDS agent ({message, level, source:"hids", eventType, ip, timestamp, metadata}), batch them, and submit via HMAC-signed POST to /api/logs/ingest. Include heartbeat, retry logic, and graceful shutdown.

**2. SVM ML Pipeline**
> Add an SVM (SVC with RBF kernel) anomaly detector to the ThreatLens ids-engine alongside the existing RandomForest and IsolationForest. The SVM should use the same 13-feature vector. Train on labeled data (binary: benign=0, attack=1). In inference, run both RF and SVM and use ensemble scoring: if either model flags anomaly with confidence > 0.7, mark as anomaly. Add evaluation metrics: accuracy, precision, recall, F1-score, confusion matrix. Save metrics in the model artifact and expose via /model-metrics API.

**3. Incident Management**
> Add an Incident module to ThreatLens: Mongoose model (title, severity, status [Open/Investigating/Resolved/Closed], assignee, linked alerts[], timeline[], _org_id), Express CRUD controller with org-isolation, auto-creation when 3+ correlated alerts fire for the same IP within the correlation window, Socket.IO emission on create/update, React Incidents page with list/detail/assign/resolve workflow.

**4. Dashboard Upgrade**
> Upgrade the ThreatLens Dashboard.jsx to add: HIDS event panel (login failures, file changes, process alerts), Agent Health grid (all registered agents with last-seen, status, version), Model Health summary card (algorithm, accuracy, last trained), Incident summary (open count by severity). Keep existing Snort/NIDS panels. Use Socket.IO for real-time updates on all new panels.

**5. Alert Correlation & Incidents**
> Enhance ThreatLens alert correlation: when upsertCorrelatedAlert creates or updates an alert, check if the org+IP+timewindow has 3+ open alerts. If so, auto-create an Incident grouping those alerts. Set incident severity to the highest alert severity. Emit `incidents:new` via Socket.IO. Add incident_id back-reference to each alert.

**6. Rules CRUD**
> Add a Rules module to ThreatLens: MongoDB model for custom detection rules (name, conditions as JSON, severity, enabled flag, _org_id), Express CRUD API with admin-only access, integration with detector.service.js to evaluate custom rules during evaluateLog(), React Rules page for create/edit/toggle/delete with a form builder for conditions.

**7. Model Health Dashboard**
> Upgrade ThreatLens ModelHealth.jsx to display: algorithm name, training timestamp, sample count, precision/recall/F1 scores, confusion matrix visualization (2x2 heatmap), feature importance chart (for RandomForest), ROC curve if available. Fetch data from new /api/model/metrics endpoint that reads training_summary from the saved model artifact.

**8. Testing**
> Write tests for ThreatLens: (a) Jest + Supertest integration tests for auth, log ingest, alert CRUD, incident CRUD APIs, (b) pytest unit tests for anomaly.py analyze_event, rule_based.py detect_attack, train_model.py training pipeline, (c) Node.js unit tests for snort-parsers.js parsing logic, detector.service.js rule evaluation. Use MongoDB Memory Server for API tests.

---

## Summary — What Your Project Actually Is Today

Your ThreatLens is a **functional NIDS + ML-based detection platform** with a real live pipeline:

```
Snort → Agent → API → Rule Engine + ML → Alerts → Socket.IO → React Dashboard
```

It is **not** yet a hybrid IDS because it lacks HIDS entirely. The ML pipeline is real but trains on synthetic data only and uses IsolationForest + RandomForest (no SVM). Several frontend pages (Incidents, Rules, ThreatIntel, Playbooks, ThreatMap) are UI shells with no backend.

The core architecture is **solid and well-engineered** — multi-tenant, properly secured, real-time capable. The upgrade path is clear: add HIDS agent, add SVM, build Incident/Rules backends, connect the empty frontend pages, and integrate a real dataset.
