# ThreatLens API Server

This is the Node.js backend for ThreatLens, providing authentication, alerting, logging, and integration with the IDS engine.

## Features
- JWT authentication with refresh token rotation (secure HTTP-only cookies)
- Role-based access control (admin, analyst, user)
- Rate limiting, helmet, and CORS for security
- Audit logging for registration and login
- Real-time events via Socket.io
- Modular REST API for alerts, logs, dashboard, and assets

## Folder Structure
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
```

## Environment Setup
Copy `.env.example` to `.env` and fill in secrets and MongoDB URI.

## Run Instructions
```bash
cd backend/api-server
npm install
npm start
```

## API Endpoints
- `POST /api/auth/register` — Register new user
- `POST /api/auth/login` — Login and receive tokens
- `POST /api/auth/refresh` — Refresh access token
- `POST /api/auth/logout` — Logout and revoke refresh token
- `GET /api/auth/me` — Get current user info

## Security Best Practices
- Use strong secrets for JWT and refresh tokens
- Set `REFRESH_COOKIE_SECURE=true` and use HTTPS in production
- Set `CORS_ORIGIN` to your frontend URL
- Never expose secrets or stack traces in production

## Troubleshooting
- If cookies are not set, check `REFRESH_COOKIE_SECURE` and CORS settings
- Ensure MongoDB is running and accessible
- Check logs for errors during registration or login

## Integration
- Connects to the Python IDS engine at the URL set in `IDS_ENGINE_URL`
- Designed to work with the ThreatLens frontend and agent
