
# ThreatLens Frontend (SOC Dashboard)

## Folder Structure
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
Copy `.env.example` to `.env` and set your backend API URL.

## Run Instructions
```bash
cd frontend
npm install
npm start
```

## Features
- JWT-based authentication with refresh tokens (secure, HTTP-only)
- Protected routes and role-aware layout
- Real-time alerts/logs via WebSocket
- Alert lifecycle management
- Log ingestion and filtering
- Health status and last detection time

## Security Best Practices
- Use HTTPS in production
- Set `REACT_APP_API_URL` to your backend API endpoint
- Never expose secrets in frontend code

## Troubleshooting
- If login/refresh fails, check browser cookies and CORS settings
- Ensure backend is running and accessible at the API URL

## Architecture

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
