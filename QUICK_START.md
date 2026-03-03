# ThreatLens Quick Start Guide

## Project Overview

ThreatLens is a **multi-tenant enterprise Security Operations Center (SOC)** platform. It collects security events from distributed agents, correlates them with ML anomaly detection, and provides real-time threat intelligence.

**Architecture**: 
- **Backend**: Node.js + Express + MongoDB
- **Agents**: Lightweight Node.js sensors on customer infrastructure  
- **Detection**: Python-based IDS rules + ML anomalies (upcoming)
- **Frontend**: React dashboard (existing)

## Getting Started

### Prerequisites

```bash
# Required versions
Node.js: 18.0.0+
npm: 9.0.0+
MongoDB: 5.0+ (local or Atlas)
.env file with database credentials
```

### Backend Setup (API Server)

```bash
cd backend/api-server

# Install dependencies
npm install

# Create .env file (copy from config/env.js for defaults)
cat > .env << EOF
NODE_ENV=development
PORT=3000
DB_URL=mongodb://localhost:27017/threatlens
JWT_SECRET=your-secret-key
CORS_ORIGIN=http://localhost:3000
EOF

# Start database (if using local MongoDB)
mongod

# In another terminal, start API server
npm start
# Server runs on http://localhost:3000
```

### Agent Setup

```bash
cd backend/agent

# Install dependencies
npm install

# Create .env file with API credentials
cp .env.example .env
# Edit .env with your ThreatLens API details:
# THREATLENS_API_URL=http://localhost:3000
# THREATLENS_API_KEY=<from dashboard>
# THREATLENS_API_SECRET=<from dashboard>
# ASSET_ID=asset-dev-01

# Start agent
npm start
# Agent collects events and sends to API
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start dev server
npm start
# Opens http://localhost:3000

# Build for production
npm run build
```

## Multi-Tenancy Concepts

### The Rule: Every Query Includes `_org_id`

This is the **most critical security rule** in the codebase.

```javascript
// ❌ WRONG - Cross-org data leak!
const alerts = await Alert.find({ severity: "Critical" });

// ✅ CORRECT - Org-isolated
const alerts = await Alert.find({ 
  _org_id: req.orgId,  // Always filter by org
  severity: "Critical" 
});
```

### The Middleware Chain

Every protected route goes through this chain:

```javascript
app.use("/api/alerts", 
  authenticate,      // Verify JWT signature
  orgIsolation,      // Extract & validate org from JWT
  alertRoutes        // Route handlers get req.orgId pre-attached
);
```

The `orgIsolation` middleware does:
1. Extract `org_id` from JWT claims
2. Validate org exists and is active
3. Attach `req.orgId` to request
4. If anything fails, return 401 Unauthorized

### The Organization Model

```javascript
// Every organization has:
{
  _id: ObjectId,
  org_id: "acme-corp",              // Unique short ID
  org_name: "ACME Corporation",
  org_plan: "enterprise",           // starter, professional, enterprise
  org_status: "active",             // active, suspended, deleted
  
  // Quotas
  ingest_quota_per_minute: 10000,   // Events/min limit
  ingest_quota_per_day: 1000000,    // Events/day limit
  
  // Features (enabled per plan)
  feature_flags: {
    real_time_alerts: true,
    correlation_engine: true,
    anomaly_detection: false,
    threat_intel: false
  },
  
  // Retention & archival
  data_retention_days: 30
}
```

## API Authentication

### For Agents (API Key + HMAC)

Agents authenticate differently from users:

```bash
# Step 1: Get API key from dashboard
# In admin panel: Settings → API Keys → Generate
# Shows: API Key (token) and API Secret (only once!)

# Step 2: Agent submits events
curl -X POST http://localhost:3000/api/ingest/v1/ingest \
  -H "X-API-Key: key_abc123xyz" \
  -H "X-Signature: $(generate_hmac_here)" \
  -H "X-Timestamp: $(date +%s%3N)" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": "asset-server-01",
    "events": [
      { "event_type": "http_request", "timestamp": "...", ... }
    ]
  }'
```

### For Users (JWT)

Users authenticate with email/password:

```bash
# Step 1: Register or login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{ "email": "user@company.com", "password": "secure" }'

# Response: { "token": "eyJhbGc..." }

# Step 2: Use token for protected routes
curl http://localhost:3000/api/alerts \
  -H "Authorization: Bearer eyJhbGc..."

# Server validates JWT and auto-filters by org
```

## Key Files & Responsibilities

### Models
- `models/Organization.js` - Root tenant entity
- `models/User.js` - **MUST have _org_id** 
- `models/APIKey.js` - Agent credentials
- `models/Asset.js` - Monitored infrastructure
- `models/Event.js` - Raw events (TTL deletion)
- `models/Alerts.js` - Generated security alerts
- `models/Log.js` - **MUST have _org_id**
- `models/AuditLog.js` - Compliance trail

### Middleware
- `middleware/auth.middleware.js` - JWT validation
- `middleware/orgIsolation.middleware.js` - **MOST CRITICAL** - Org context extraction
- `middleware/ingest.middleware.js` - API key + HMAC validation
- `middleware/authorize.middleware.js` - Role-based (admin vs analyst)

### Controllers
- `controllers/auth.controller.js` - Registration, login, org creation
- `controllers/alerts.controller.js` - Alert CRUD (all queries filtered by _org_id)
- `controllers/logs.controller.js` - Log CRUD (all queries filtered by _org_id)
- `controllers/apikey.controller.js` - API key management
- `controllers/asset.controller.js` - Asset CRUD
- `controllers/ingest.controller.js` - Event ingestion

### Routes
- All protected routes (`alerts`, `logs`, `dashboard`, `assets`, `admin/*`) apply `orgIsolation`
- Ingest routes use API key auth instead (different model for agents)

## Common Development Tasks

### Add New Endpoint

```javascript
// 1. Create controller function in controllers/alerts.controller.js
const getAlertsByUser = async (req, res) => {
  try {
    // ✅ ALWAYS filter by org
    const alerts = await Alert.find({
      _org_id: req.orgId,          // CRITICAL
      user: req.query.user,
      severity: "Critical"
    });
    return res.json({ data: alerts });
  } catch (error) {
    return res.status(500).json({ message: "Error" });
  }
};

// 2. Add route in routes/alerts.routes.js
router.get("/by-user", authenticate, orgIsolation, getAlertsByUser);
// Note: No need to pass orgIsolation again if it's in server.js mounting
// But adding it here is defensive and explicit

// 3. No server.js changes needed (route already mounted)
```

### Add New Model with Multi-Tenancy

```javascript
// Always include _org_id in schema
const mySchema = new mongoose.Schema({
  _org_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Organization",
    required: true,           // CRITICAL
    index: true               // For performance
  },
  
  name: String,
  data: {}
});

// Create compound indexes for org + other fields
mySchema.index({ _org_id: 1, status: 1 });
mySchema.index({ _org_id: 1, createdAt: -1 });

module.exports = mongoose.model("MyModel", mySchema);
```

### Debug Multi-Tenant Queries

```bash
# Enable Mongoose query logging
export DEBUG=mongoose:*

# Check which org is being used
console.log("Filtering by org:", req.orgId);
console.log("User from JWT:", req.user.sub);

# Verify _org_id is in every database call
grep -r "_org_id" controllers/  # Should have many hits
```

### Test Agent Integration

```bash
# 1. Create organization & user
POST /api/auth/register
{ "email": "admin@test.com", "password": "pwd" }

# 2. Create asset
POST /api/assets
{ "asset_name": "Test Server", "asset_type": "web_server" }
Response: { "asset_id": "asset-xyz" }

# 3. Generate API key in admin panel
Returns: token + secret (save both!)

# 4. Configure agent
export THREATLENS_API_KEY="token_..."
export THREATLENS_API_SECRET="secret_..."
export ASSET_ID="asset-xyz"

# 5. Run agent
cd backend/agent
npm start

# 6. Verify events are received
GET /api/ingest/v1/stats
Should show event counts increasing
```

## Troubleshooting

### Error: "Invalid API Key"
```
Cause: THREATLENS_API_KEY doesn't match any key in database
Solution: 
1. Generate new key in admin dashboard
2. Copy token AND secret
3. Set both in agent .env
```

### Error: "Invalid HMAC Signature"
```
Cause: Secret key mismatch or timestamp out of window
Solution:
1. Verify secret is exactly right (copy from dashboard)
2. Check agent system clock is within ±5 minutes of server
3. Ensure timestamp is in milliseconds (not seconds)
```

### Error: "Unauthorized - org not found"
```
Cause: User's JWT has org_id that doesn't exist in Organization collection
Solution:
1. Check user has _org_id field set
2. Verify Organization document exists for that _org_id
3. Re-login to get fresh JWT
```

### Error: "Cross-org data leak" (testing)
```
If you see data from other organizations:
1. Find the query missing _org_id filter
2. Add: filters._org_id = req.orgId;
3. Add test case to prevent regression
```

## Performance Tips

### Database
```javascript
// ✅ Good: Uses compound index
Alert.find({ _org_id: org1, severity: "Critical" })

// ❌ Bad: Forces full scan
Alert.find({ severity: "Critical" }).then(a => a.filter(x => x._org_id === org1))
```

### Queries
```javascript
// ✅ Good: Parallel queries
await Promise.all([
  Alert.countDocuments({ _org_id: org1 }),
  Log.countDocuments({ _org_id: org1 })
])

// ❌ Bad: Sequential
const alerts = await Alert.countDocuments({ _org_id: org1 });
const logs = await Log.countDocuments({ _org_id: org1 });
```

### Caching
```javascript
// Cache organization settings in memory
class OrgCache {
  static cache = new Map();
  
  static async get(orgId) {
    if (!this.cache.has(orgId)) {
      this.cache.set(orgId, await Organization.findById(orgId));
    }
    return this.cache.get(orgId);
  }
}

// Use in requests
const org = await OrgCache.get(req.orgId);
```

## Testing

### Unit Test Template

```javascript
describe("alerts.controller", () => {
  let org1, org2, user1, alert1, alert2;

  beforeAll(async () => {
    // Create two orgs
    org1 = await Organization.create({ org_id: "test-org-1", org_name: "Org 1" });
    org2 = await Organization.create({ org_id: "test-org-2", org_name: "Org 2" });
    
    // Create users in each org
    user1 = await User.create({ email: "user1@org1.com", _org_id: org1._id });
    // ...
  });

  test("listAlerts filters by organization", async () => {
    // Create alerts in different orgs
    alert1 = await Alert.create({ severity: "Critical", _org_id: org1._id });
    alert2 = await Alert.create({ severity: "Critical", _org_id: org2._id });

    // Mock request
    const req = { orgId: org1._id };
    
    // Call controller
    await listAlerts(req, res);
    
    // Verify only org1 alert returned
    expect(res.json.call.args[0][0].data).toHaveLength(1);
    expect(res.json.call.args[0][0].data[0]._id).toEqual(alert1._id);
  });
});
```

## Deployment

### Production Checklist

```bash
# ✅ Environment
NODE_ENV=production
JWT_SECRET=<long random string>
DB_URL=<production MongoDB>

# ✅ Security
CORS_ORIGIN=https://yourdomain.com (not *)
refreshCookieSecure=true
refreshCookieSameSite=Strict

# ✅ Scaling
API_CONCURRENCY=100
DB_CONNECTION_POOL=50

# ✅ Monitoring
LOG_LEVEL=info
SENTRY_DSN=<error tracking>

# ✅ Database
mongodb-backup: daily
indexes: created
TTL: enabled for Event collection

# ✅ API
rate-limiting: enabled
request validation: enabled
audit logging: enabled
```

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    AGENTS (Customer Infra)                  │
│  ┌──────┐  ┌──────┐  ┌──────┐    Collect: Logs, Network     │
│  │Agent1│  │Agent2│  │Agent3│    → Buffer → HMAC-sign → API │
│  └──┬───┘  └──┬───┘  └──┬───┘                               │
│     │         │         │                                    │
│     └─────────┼─────────┘                                    │
│               │                                              │
│               ▼                                              │
├──────────────────────────────────────────────────────────────┤
│              API Key + HMAC Validation                       │
│              /api/ingest/v1/ingest                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Event Ingestion Layer                               │   │
│  │  - Store with _org_id & _asset_id                    │   │
│  │  - Publish to detection queue (TODO)                │   │
│  └──────────────────────────────────────────────────────┘   │
│               │                                              │
│               ▼                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  MongoDB (Multi-Tenant Database)                     │   │
│  │  - Organization (root entity)                         │   │
│  │  - User (email unique per org)                        │   │
│  │  - Asset (monitored infrastructure)                   │   │
│  │  - Event (raw ingested events + TTL)                  │   │
│  │  - Alert (generated security alerts)                  │   │
│  │  - APIKey (agent credentials)                         │   │
│  │  ✅ Every collection: _org_id indexed                │   │
│  └──────────────────────────────────────────────────────┘   │
│               │                                              │
│               ▼                                              │
├──────────────────────────────────────────────────────────────┤
│              JWT + Organization Isolation                    │
│              Protected Routes                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  /api/alerts, /api/logs, /api/dashboard, /api/assets │   │
│  │  ✅ All queries: WHERE _org_id = req.orgId           │   │
│  │  ✅ All responses: Only this org's data              │   │
│  └──────────────────────────────────────────────────────┘   │
│               │                                              │
│               ▼                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  FRONTEND DASHBOARD (React)                          │   │
│  │  - Alert management                                   │   │
│  │  - Asset monitoring                                   │   │
│  │  - Statistics & health                                │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

## Resources

- [Multi-Tenancy Best Practices](./ARCHITECTURE_AND_DESIGN.md)
- [Implementation Progress](./IMPLEMENTATION_PROGRESS.md)
- [Agent Documentation](./backend/agent/README.md)
- [API Endpoints](./API_ENDPOINTS.md) (TODO)

## Support

Issues? Check:
1. logs in `backend/api-server` directory
2. agent logs in `backend/agent` directory
3. MongoDB connectivity
4. JWT token expiry
5. Organization exists with correct _org_id

---

**ThreatLens** - The Open Security Intelligence Platform
