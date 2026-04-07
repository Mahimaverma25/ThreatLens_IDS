# ThreatLens - Intelligent Threat Detection & Response System

A comprehensive **IDS (Intrusion Detection System)** platform combining real-time network monitoring, ML-based anomaly detection, and a modern React dashboard for security event management.

---

## 🚀 Quick Start (5 minutes)

### Prerequisites
- Node.js 18+
- MongoDB running
- Python 3.8+ (for IDS engine)

### 1. Start Backend API Server
```bash
cd backend/api-server
npm install
npm run dev  # Starts on http://localhost:3000
```

### 2. Start Agent (Event Collector)
```bash
cd backend/agent
npm install
npm run dev  # Starts collecting events
```

### 3. Start Frontend Dashboard
```bash
cd frontend
npm install
npm start  # Starts on http://localhost:3000
```

### 4. Start IDS Engine (Python)
```bash
cd backend/ids-engine
pip install -r requirements.txt
python app.py  # Starts on http://localhost:5001
```

Or use the batch script:
```bash
./START_ALL.bat  # Launches all components
```

---

## 📋 Project Structure

```
ThreatLens/
├── backend/
│   ├── api-server/          # Express.js REST API & WebSocket  
│   │   ├── controllers/     # Business logic
│   │   ├── middleware/      # Auth, validation, rate limiting
│   │   ├── models/          # MongoDB schemas
│   │   ├── routes/          # API endpoints
│   │   ├── services/        # Core services
│   │   └── utils/           # Helpers & utilities
│   ├── agent/               # Event collection agent
│   │   ├── services/        # API client, event collection
│   │   └── agent.js         # Main agent entry point
│   └── ids-engine/          # Python IDS anomaly detection
│       ├── detector/        # Detection rules & ML models
│       ├── api/            # Flask API routes
│       └── models/         # ML model loading
├── frontend/                # React.js dashboard
│   ├── src/
│   │   ├── components/      # Reusable UI components
│   │   ├── pages/          # Page components
│   │   ├── services/       # API client
│   │   ├── context/        # Auth context
│   │   └── hooks/          # Custom hooks
│   └── public/             # Static assets
└── Documentation/          # Setup guides & deployment info
```

---

## 🔐 Authentication & Security

### API Authentication (Agent → Backend)
The agent uses **API Key + HMAC-SHA256** signature authentication:

1. **Headers Required**:
   - `X-API-Key`: Token for authentication
   - `X-Timestamp`: Unix seconds timestamp
   - `X-Signature`: HMAC-SHA256(payloadHash.timestamp, secret)
   - `X-Asset-ID`: Device/server identifier

2. **Setup API Key**:
   ```bash
   cd backend/api-server
   node setup-dev-keys.js  # Creates test org, asset, and API key
   ```
   
   Then update `backend/agent/.env`:
   ```env
   THREATLENS_API_URL=http://localhost:3000
   THREATLENS_API_KEY=<token-from-setup-script>
   THREATLENS_API_SECRET=tlk_secret_dev
   ASSET_ID=agent-001
   ```

### User Authentication (Dashboard)
- **JWT tokens** for user login/logout
- **Refresh tokens** for session management
- **Organization isolation** - Users can only see their org's data

---

## ⚠️ Common Issues & Fixes

### 1. Agent Gets 401 "Invalid API Key"
**Fix**: Run the setup script to create valid API key in MongoDB:
```bash
cd backend/api-server
node setup-dev-keys.js
```
See: [FIX_401_INVALID_API_KEY.md](FIX_401_INVALID_API_KEY.md)

### 2. Frontend Can't Connect to Backend
**Issue**: Frontend proxy pointing to wrong port
**Fix**: Ensure `frontend/package.json` has `"proxy": "http://localhost:3000"`

### 3. MongoDB Connection Failed
**Fix**: Ensure MongoDB is running and MONGO_URI in `.env` is correct:
```bash
# Check MongoDB
mongod --version

# Or use Docker
docker run -d -p 27017:27017 mongo:latest
```

---

## 📚 Detailed Guides

| Guide | Purpose |
|-------|---------|
| [QUICK_START.md](QUICK_START.md) | Step-by-step setup for all components |
| [ARCHITECTURE_AND_DESIGN.md](ARCHITECTURE_AND_DESIGN.md) | System architecture & tech stack |
| [FIX_401_INVALID_API_KEY.md](FIX_401_INVALID_API_KEY.md) | **Setup agent & resolve 401 errors** |
| [BACKEND_FIXES_REPORT.md](BACKEND_FIXES_REPORT.md) | Backend improvements & fixes |
| [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) | Production deployment steps |

---

## 🛠️ Tech Stack

### Frontend
- **React 19** - UI framework
- **Axios** - HTTP client
- **Socket.io-client** - Real-time updates
- **React Router v6** - Routing

### Backend (Node.js/Express)
- **Express.js** - REST API & WebSocket server
- **MongoDB** - Database
- **JWT + API Keys** - Authentication
- **Winston** - Logging
- **Helmet** - Security headers
- **Express Rate Limit** - DDoS protection

### IDS Engine (Python)
- **Flask** - REST API
- **Scikit-learn** - ML anomaly detection
- **NumPy/Pandas** - Data processing
- **Snort Integration** - Rule-based detection

---

## 🧪 Testing

### Run Tests
```bash
# Frontend tests
cd frontend && npm test

# Backend tests (if configured)
cd backend/api-server && npm test

# Agent tests
cd backend/agent && npm test
```

### Manual Testing
```bash
# Test API endpoint
curl -X GET http://localhost:3000/api/dashboard/stats \
  -H "Authorization: Bearer <jwt-token>"

# Check agent connection
tail -f backend/agent/agent-combined.log
```

---

## 📋 Environment Variables

Create `.env` files in each directory:

**backend/api-server/.env**:
```env
MONGO_URI=mongodb://localhost:27017/threatLens
JWT_SECRET=your-jwt-secret-key
JWT_EXPIRY=7d
PORT=3000
NODE_ENV=development
```

**backend/agent/.env**:
```env
THREATLENS_API_URL=http://localhost:3000
THREATLENS_API_KEY=<from-setup-script>
THREATLENS_API_SECRET=tlk_secret_dev
ASSET_ID=agent-001
BATCH_SIZE=50
LOG_LEVEL=info
```

**frontend/.env** (optional):
```env
REACT_APP_API_URL=http://localhost:3000
```

---

## 🚀 Production Deployment

1. **Build Frontend**:
   ```bash
   cd frontend && npm run build
   ```

2. **Deploy Backend**:
   - Use Node process manager (PM2, systemd, etc.)
   - Set `NODE_ENV=production`
   - Enable HTTPS
   - Use strong JWT/API secrets

3. **Database**:
   - MongoDB Atlas or self-hosted
   - Enable authentication
   - Set IP whitelist

4. **IDS Engine**:
   - Deploy as separate service
   - Use Gunicorn/uWSGI for production

See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for detailed steps.

---

## 📊 API Endpoints

### Authentication
- `POST /api/auth/register` - Create account
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh` - Refresh JWT token
- `POST /api/auth/logout` - Logout

### Logs & Events
- `POST /api/logs/ingest` - Agent submits events (requires API Key)
- `GET /api/logs` - Get logs (requires JWT)
- `POST /api/alerts` - Create alert rule

### Dashboard
- `GET /api/dashboard/stats` - System statistics
- `GET /api/dashboard/health` - Health check

### Admin
- `POST /api/admin/api-keys` - Create API key
- `GET /api/admin/api-keys` - List API keys

---

## 🔗 Debugging & Support

### Check Logs
```bash
# Backend logs
tail -f backend/api-server/logs/app.log

# Agent logs
tail -f backend/agent/agent-combined.log

# Frontend console
Browser DevTools → Console
```

### Enable Debug Mode
```bash
# Backend
DEBUG=* npm run dev

# Agent
LOG_LEVEL=debug node agent.js
```

### Common Commands
```bash
# Clear node_modules and reinstall
rm -r node_modules && npm install

# Reset MongoDB (caution!)
mongo threatLens --eval "db.dropDatabase()"

# Check if ports are in use
netstat -ano | findstr :3000  # Windows
lsof -i:3000  # macOS/Linux
```

---

## 📝 Project Status

✅ **Completed**
- Core API server with authentication
- Agent event collection & HMAC signing
- MongoDB integration
- REST endpoints for alerts
- Real-time WebSocket updates
- Python IDS detection engine
- React dashboard

🔄 **In Progress**
- Advanced ML models
- Custom rule builder UI
- Export/reporting features

---

## 📄 License

MIT License - See LICENSE file

---

## 👥 Contributors

ThreatLens Development Team

---

## ❓ Questions?

- Check [QUICK_START.md](QUICK_START.md) for setup help
- Review [FIX_401_INVALID_API_KEY.md](FIX_401_INVALID_API_KEY.md) for authentication issues
- See [BACKEND_FIXES_REPORT.md](BACKEND_FIXES_REPORT.md) for technical details

**Last Updated**: March 28, 2026
