# ThreatLens Backend (Production-Ready IDS API)

## Backend Folder Structure

```
api-server/
    config/
    controllers/
    logs/
    middleware/
    models/
    routes/
    services/
    utils/
    server.js
ids-engine/
```

## Environment Setup

Create a new file using [backend/api-server/.env.example](api-server/.env.example) as reference.

## Run Instructions

1) Install dependencies

```
cd backend/api-server
npm install
```

2) Start the API server

```
npm run dev
```

3) Run the IDS engine

```
cd ../ids-engine
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

## Core API Documentation

### Auth

- POST `/api/auth/register`
- POST `/api/auth/login`
- POST `/api/auth/refresh`
- POST `/api/auth/logout`
- GET `/api/auth/me`

### Alerts

- GET `/api/alerts?status=&severity=&search=&ip=&page=&limit=`
- GET `/api/alerts/:id`
- PATCH `/api/alerts/:id` (status, note)
- POST `/api/alerts/scan`

### Logs

- GET `/api/logs?level=&source=&search=&ip=&page=&limit=`
- POST `/api/logs`
- POST `/api/logs/ingest` (X-API-KEY)
- POST `/api/logs/upload` (multipart/form-data: file)
- POST `/api/logs/simulate?count=`

### Dashboard

- GET `/api/dashboard/stats`
- GET `/api/dashboard/health`

## Security Features

- JWT access tokens + refresh token rotation (HTTP-only cookies)
- bcrypt password hashing
- rate limiting and helmet
- audit logs for registration + login
- role-based access control (Admin / Analyst)
- request logging + detection correlation

## IDS Detection Rules (Server-Side)

- Brute force login attempts
- Unauthorized admin access
- Request burst / DoS behavior
- Suspicious IP activity

## Real-Time Events (Socket.io)

- `alerts:new`
- `alerts:update`
- `logs:new`

## Architecture

┌──────────────────────────────┐
│        Frontend (SOC UI)     │
│        React Dashboard       │
└──────────────┬──────────────┘
                             │ REST + WebSocket
┌──────────────▼──────────────┐
│     Backend (Control API)   │
│ Auth, Alerts, Logs, RBAC    │
└──────────────┬──────────────┘
                             │
┌──────────────▼──────────────┐
│  IDS Engine (Python Core)   │
│  Rule + Anomaly Detection   │
└──────────────┬──────────────┘
                             │
┌──────────────▼──────────────┐
│     Data Sources            │
│  Logs, Simulated Traffic    │
└──────────────────────────────┘
