# ThreatLens Frontend (SOC Dashboard)

## Frontend Folder Structure

```
src/
	components/
	context/
	hooks/
	layout/
	pages/
	services/
	styles/
```

## Environment Setup

Create a new file using [frontend/.env.example](.env.example) as reference.

## Run Instructions

```
cd frontend
npm install
npm start
```

## Features

- JWT-based authentication with refresh tokens
- Protected routes and role-aware layout
- Real-time alerts/logs via WebSocket
- Alert lifecycle management
- Log ingestion and filtering
- Health status and last detection time

# real architecture

Client Website / Server
        |
        |  (Logs + Traffic)
        v
ThreatLens Agent (Lightweight)
        |
        |  Secure HTTPS / gRPC
        v
ThreatLens Cloud Platform
 ├── Ingestion Layer
 ├── Detection Engine (Rules + ML)
 ├── Correlation Engine
 ├── Alerting System
 ├── Dashboard (SOC View)
