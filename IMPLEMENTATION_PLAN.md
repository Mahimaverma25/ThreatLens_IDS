# ThreatLens Implementation Action Plan

**Status**: Blueprint for Production Migration  
**Updated**: February 2026  
**Owner**: Development Team

---

## Current State vs. Target State

### What You Have Now
- ✅ Basic Express API with auth/alerts/logs routes
- ✅ Simple rule-based detection (simulated)
- ⚠️ No agent infrastructure (traffic is SIMULATED)
- ⚠️ No multi-tenant support (single org)
- ⚠️ Detection runs on fake data
- ⚠️ No correlation engine
- ⚠️ No real message queue

### What You Need to Build
1. **ThreatLens Agent** (Node.js or Python)
2. **Secure Ingestion API** (with API key validation)
3. **Real Detection Engine** (with stateful counters & ML)
4. **Correlation Engine** (incident grouping)
5. **Multi-Tenant Architecture** (org isolation)
6. **Message Queue** (Kafka, Redis, or RabbitMQ)
7. **Professional Deployment** (Docker, Kubernetes)

---

## Priority 1: Multi-Tenant Architecture (DO THIS FIRST)

### 1.1 Add Org Isolation Middleware

**File**: `backend/api-server/middleware/orgIsolation.middleware.js`

```javascript
/**
 * Ensures all database queries include org_id filter.
 * Prevents one tenant from accessing another's data.
 */

const OrganizationModel = require('../models/Organization');

const orgIsolation = async (req, res, next) => {
  // Get org_id from JWT (already decoded by auth middleware)
  const userId = req.user._id;
  const userDoc = await UserModel.findById(userId);
  
  if (!userDoc) {
    return res.status(401).json({ error: 'User not found' });
  }
  
  // Attach org to request context
  req.orgId = userDoc._org_id;
  req.org = await OrganizationModel.findById(req.orgId);
  
  if (!req.org) {
    return res.status(403).json({ error: 'Organization not found' });
  }
  
  // Middleware for route handlers
  res.locals.orgId = req.orgId;
  res.locals.org = req.org;
  
  next();
};

module.exports = { orgIsolation };
```

**Update Every Query**: Add `_org_id` filter

```javascript
// BEFORE (vulnerable to cross-tenant access)
const alerts = await Alert.find({ status: 'new' });

// AFTER (org-isolated)
const alerts = await Alert.find({ 
  _org_id: req.orgId,  // ← CRITICAL
  status: 'new' 
});
```

### 1.2 MongoDB Schema Updates

Create and run migrations to add `_org_id` to all collections:

```javascript
// backend/api-server/models/index.js - Add _org_id to schemas

// User.js
const userSchema = new Schema({
  _id: ObjectId,
  _org_id: { type: ObjectId, ref: 'Organization', required: true, index: true },
  email: { type: String, required: true },
  // ... rest of fields
});

// Alert.js  
const alertSchema = new Schema({
  _id: ObjectId,
  _org_id: { type: ObjectId, ref: 'Organization', required: true, index: true },
  // ... rest of fields
});

// Add indexes for org queries
userSchema.index({ _org_id: 1, email: 1 }, { unique: true });
alertSchema.index({ _org_id: 1, created_at: -1 });
```

### 1.3 Create Organization Model

```javascript
// backend/api-server/models/Organization.js
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const organizationSchema = new Schema({
  org_id: { type: String, unique: true, required: true }, // org_123456
  org_name: { type: String, required: true },
  org_domain: String,
  org_plan: { 
    type: String, 
    enum: ['free', 'starter', 'professional', 'enterprise'],
    default: 'starter'
  },
  
  // Feature flags
  features: {
    anomaly_detection: { type: Boolean, default: false },
    correlation_engine: { type: Boolean, default: true },
    custom_rules: { type: Boolean, default: false },
  },
  
  // Quotas
  ingest_quota_per_minute: { type: Number, default: 1000 },
  ingest_quota_per_day: { type: Number, default: 100_000_000 },
  
  status: { type: String, enum: ['active', 'suspended'], default: 'active' },
  created_at: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Organization', organizationSchema);
```

---

## Priority 2: Secure Ingestion API (Agent ← → Backend)

### 2.1 Create APIKey Model

```javascript
// backend/api-server/models/APIKey.js
const mongoose = require('mongoose');
const crypto = require('crypto');

const apiKeySchema = new mongoose.Schema({
  _org_id: { type: ObjectId, ref: 'Organization', required: true },
  _asset_id: { type: ObjectId, ref: 'Asset', required: true },
  
  // Public token (shown once during creation)
  token: { type: String, unique: true }, // tlk_org123_...
  
  // Secret (used for HMAC signing)
  secret_key: { type: String }, // Stored hashed!
  
  name: String,
  last_used_at: Date,
  is_active: { type: Boolean, default: true },
  expires_at: { type: Date, default: () => new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) },
  
  created_at: { type: Date, default: Date.now },
});

// Hash secret before saving
apiKeySchema.pre('save', function(next) {
  if (!this.secret_key) {
    this.secret_key = crypto.randomBytes(32).toString('hex');
  }
  
  // Hash it for storage (one-way)
  this.secret_key_hash = crypto.createHash('sha256').update(this.secret_key).digest('hex');
  
  next();
});

module.exports = mongoose.model('APIKey', apiKeySchema);
```

### 2.2 Create Ingestion Routes

```javascript
// backend/api-server/routes/ingest.routes.js
const express = require('express');
const router = express.Router();
const { validateAPIKey, validateIngestPayload } = require('../middleware/ingest.middleware');
const IngestController = require('../controllers/ingest.controller');

// All routes require API key (not JWT)
router.post('/v1/ingest', 
  validateAPIKey,
  validateIngestPayload,
  IngestController.ingestEvents
);

router.get('/v1/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

module.exports = router;
```

### 2.3 Add to Main Server

```javascript
// backend/api-server/server.js
// Add this line with other routes:
const ingestRoutes = require('./routes/ingest.routes');
app.use('/api/ingest', ingestRoutes); // ← Add this
```

### 2.4 Validate Ingestion Requests

```javascript
// backend/api-server/middleware/ingest.middleware.js
const crypto = require('crypto');
const APIKey = require('../models/APIKey');

const validateAPIKey = async (req, res, next) => {
  const apiKeyHeader = req.headers['x-api-key'];
  const timestamp = req.headers['x-timestamp'];
  const signature = req.headers['x-signature'];
  const assetId = req.headers['x-asset-id'];

  // Validate headers exist
  if (!apiKeyHeader || !timestamp || !signature || !assetId) {
    return res.status(400).json({
      error: 'Missing required headers: X-API-Key, X-Timestamp, X-Signature, X-Asset-ID'
    });
  }

  // Verify timestamp is recent (±5 minutes)
  const now = Math.floor(Date.now() / 1000);
  const ts = parseInt(timestamp, 10);
  if (Math.abs(now - ts) > 300) {
    return res.status(401).json({
      error: 'Request timestamp too old (replay protection)',
      server_time: now,
      client_time: ts
    });
  }

  try {
    // Look up API key
    const apiKeyRecord = await APIKey.findOne({
      token: apiKeyHeader,
      is_active: true,
      expires_at: { $gt: new Date() }
    }).populate('_org_id').populate('_asset_id');

    if (!apiKeyRecord) {
      return res.status(401).json({ error: 'Invalid or expired API key' });
    }

    // Verify HMAC signature
    const payload = JSON.stringify(req.body);
    const message = `${payload}.${timestamp}`;
    const expectedSig = crypto
      .createHmac('sha256', apiKeyRecord.secret_key)
      .update(message)
      .digest('hex');

    if (signature !== expectedSig) {
      return res.status(401).json({ error: 'Invalid request signature' });
    }

    // Attach to request
    req.apiKey = apiKeyRecord;
    req.orgId = apiKeyRecord._org_id._id;
    req.assetId = apiKeyRecord._asset_id._id;

    // Rate limit check
    const rateLimitKey = `ingest:${apiKeyRecord._id}`;
    const currentCount = await req.app.locals.redis.incr(rateLimitKey);
    
    if (currentCount === 1) {
      await req.app.locals.redis.expire(rateLimitKey, 60);
    }

    const quota = apiKeyRecord._org_id.ingest_quota_per_minute || 1000;
    if (currentCount > quota) {
      return res.status(429).json({
        error: 'Rate limit exceeded',
        limit: quota,
        retry_after: 60
      });
    }

    next();
  } catch (err) {
    console.error('[Ingest Auth Error]', err);
    res.status(500).json({ error: 'Authentication service error' });
  }
};

const validateIngestPayload = (req, res, next) => {
  if (!Array.isArray(req.body.events) || req.body.events.length === 0) {
    return res.status(400).json({
      error: 'events must be non-empty array'
    });
  }

  if (req.body.events.length > 10000) {
    return res.status(413).json({
      error: 'events array too large (max 10000)'
    });
  }

  // Validate event structure
  const errors = [];
  for (let i = 0; i < Math.min(req.body.events.length, 10); i++) {
    const evt = req.body.events[i];
    if (!evt.event_id) errors.push(`Event ${i}: missing event_id`);
    if (!evt.timestamp) errors.push(`Event ${i}: missing timestamp`);
    if (!evt.event_type) errors.push(`Event ${i}: missing event_type`);
  }

  if (errors.length > 0) {
    return res.status(400).json({
      error: 'Payload validation failed',
      details: errors
    });
  }

  next();
};

module.exports = { validateAPIKey, validateIngestPayload };
```

### 2.5 Ingest Controller

```javascript
// backend/api-server/controllers/ingest.controller.js
const Event = require('../models/Event');
const Queue = require('../services/queue.service');

class IngestController {
  static async ingestEvents(req, res) {
    const { events } = req.body;
    const orgId = req.orgId;
    const assetId = req.assetId;
    const batchId = require('uuid').v4();

    try {
      // Normalize events with org_id
      const enrichedEvents = events.map(e => ({
        ...e,
        _org_id: orgId,
        _asset_id: assetId,
        _batch_id: batchId,
        _ingested_at: new Date(),
      }));

      // Store in MongoDB (hot storage)
      await Event.insertMany(enrichedEvents, { ordered: false });

      // Queue for async processing
      for (const evt of enrichedEvents) {
        await Queue.publish('inbound:events', JSON.stringify({
          ...evt,
          source: 'agent'
        }));
      }

      console.log(`[Ingest] ${events.length} events from org ${orgId}`);

      // Return 202 Accepted
      res.status(202).json({
        status: 'accepted',
        batch_id: batchId,
        events_accepted: events.length
      });

    } catch (err) {
      console.error('[Ingest Error]', err);
      res.status(500).json({ error: 'Ingestion failed' });
    }
  }
}

module.exports = IngestController;
```

---

## Priority 3: ThreatLens Agent (Critical!)

### 3.1 Agent Project Structure

```bash
# Create agent directory
mkdir -p backend/agent
cd backend/agent
npm init -y
npm install --save axios crypto uuid tail uuid dotenv
```

### 3.2 Agent Configuration File

```javascript
// backend/agent/config.example.json
{
  "organization": {
    "org_id": "org_123456",
    "api_key": "tlk_org123_abc123def456abc123..."
  },
  "asset": {
    "asset_id": "srv-prod-001",
    "asset_name": "Production API Server",
    "environment": "production",
    "criticality": "critical"
  },
  "ingestion": {
    "api_endpoint": "https://api.threatslens.io",
    "tls_verify": true,
    "tls_ca_bundle": "/etc/ssl/certs/ca-bundle.crt"
  },
  "collectors": [
    {
      "type": "file",
      "path": "/var/log/nginx/access.log",
      "format": "nginx_combined",
      "enabled": true
    },
    {
      "type": "file",
      "path": "/var/log/auth.log",
      "format": "syslog",
      "enabled": true
    }
  ],
  "buffer": {
    "max_events": 5000,
    "batch_size": 500,
    "flush_interval_seconds": 10
  },
  "transmission": {
    "timeout_seconds": 10,
    "retry_max_attempts": 3,
    "retry_backoff_seconds": 5
  }
}
```

### 3.3 Agent Main Class

```javascript
// backend/agent/src/agent.js
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const { v4: uuidv4 } = require('uuid');
const { Tail } = require('tail');

const LogParser = require('./parsers/logParser');
const EventBuffer = require('./buffer/eventBuffer');
const SecurityHandler = require('./security/securityHandler');

class ThreatLensAgent {
  constructor(configPath) {
    this.config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    this.eventBuffer = new EventBuffer(
      this.config.buffer.max_events,
      this.config.buffer.batch_size
    );
    this.parsers = new Map();
    this.watchers = [];
    this.security = new SecurityHandler(this.config);
    this.running = false;
  }

  async start() {
    console.log(`[Agent] Starting for asset: ${this.config.asset.asset_id}`);
    this.running = true;

    // Setup file watchers
    for (const source of this.config.collectors) {
      if (!source.enabled) continue;
      
      if (source.type === 'file') {
        this._setupFileWatcher(source);
      }
    }

    // Start transmission loop
    this.transmissionInterval = setInterval(
      () => this._transmit(),
      this.config.buffer.flush_interval_seconds * 1000
    );

    console.log('[Agent] Started successfully');
  }

  _setupFileWatcher(source) {
    const parser = new LogParser(source.format);
    const tail = new Tail(source.path, { follow: true });

    tail.on('line', (line) => {
      try {
        const event = parser.parse(line);
        
        // Enrich with agent context
        event.event_id = uuidv4();
        event.timestamp = new Date().toISOString();
        event.asset_id = this.config.asset.asset_id;
        event.org_id = this.config.organization.org_id;

        this.eventBuffer.push(event);
      } catch (err) {
        // Ignore parse errors
      }
    });

    tail.on('error', (err) => {
      console.error(`[Tail Error] ${source.path}:`, err.message);
    });

    this.watchers.push(tail);
  }

  async _transmit() {
    const batch = this.eventBuffer.getBatch();
    if (batch.length === 0) return;

    try {
      await this._sendToAPI(batch);
      console.log(`[Agent] Transmitted ${batch.length} events`);
    } catch (err) {
      console.error(`[Transmission Error]`, err.message);
      this.eventBuffer.requeue(batch);
    }
  }

  async _sendToAPI(events) {
    return new Promise((resolve, reject) => {
      const payload = {
        events: events,
        metadata: {
          agent_version: '1.0.0',
          agent_hostname: require('os').hostname(),
          timestamp: new Date().toISOString()
        }
      };

      const { signature, timestamp } = this.security.signPayload(payload);

      const url = new URL(this.config.ingestion.api_endpoint);
      const options = {
        hostname: url.hostname,
        port: 443,
        path: '/api/ingest/v1/ingest',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': this.config.organization.api_key,
          'X-Timestamp': timestamp,
          'X-Signature': signature,
          'X-Asset-ID': this.config.asset.asset_id
        },
        rejectUnauthorized: this.config.ingestion.tls_verify
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          if (res.statusCode === 202 || res.statusCode === 200) {
            resolve();
          } else if (res.statusCode === 401) {
            reject(new Error(`Unauthorized: ${data}`));
          } else {
            reject(new Error(`API Error ${res.statusCode}: ${data}`));
          }
        });
      });

      req.on('error', reject);
      req.setTimeout(this.config.transmission.timeout_seconds * 1000);
      req.write(JSON.stringify(payload));
      req.end();
    });
  }

  stop() {
    console.log('[Agent] Stopping...');
    this.running = false;
    this.watchers.forEach(w => w.unwatch());
    clearInterval(this.transmissionInterval);
  }
}

if (require.main === module) {
  const configPath = process.argv[2] || './config.json';
  const agent = new ThreatLensAgent(configPath);
  agent.start().catch(err => {
    console.error('[Fatal]', err);
    process.exit(1);
  });
  
  // Graceful shutdown
  process.on('SIGTERM', () => agent.stop());
  process.on('SIGINT', () => agent.stop());
}

module.exports = ThreatLensAgent;
```

### 3.4 Log Parser

```javascript
// backend/agent/src/parsers/logParser.js
class LogParser {
  constructor(format) {
    this.format = format;
  }

  parse(line) {
    if (this.format === 'nginx_combined') {
      return this._parseNginxCombined(line);
    } else if (this.format === 'syslog') {
      return this._parseSyslog(line);
    }
    throw new Error(`Unknown format: ${this.format}`);
  }

  _parseNginxCombined(line) {
    // Pattern: 192.168.1.1 - user [09/Feb/2026:10:30:45 +0000] "GET /api/users HTTP/1.1" 200 1234 "referer" "user-agent"
    const regex = /(\S+) - (\S+) \[(.+?)\] "(\w+) (.+?) (\S+)" (\d+) (\d+|-) "(.+?)" "(.+?)"/;
    const match = line.match(regex);
    
    if (!match) throw new Error('Could not parse Nginx log');

    return {
      event_type: 'http_request',
      source_ip: match[1],
      user: match[2],
      timestamp: new Date(match[3]).toISOString(),
      http_method: match[4],
      http_path: match[5],
      protocol: match[6],
      http_status: parseInt(match[7], 10),
      payload_size: match[8],
      http_referer: match[9],
      http_user_agent: match[10],
      raw: line
    };
  }

  _parseSyslog(line) {
    // Pattern: Feb 9 10:30:45 hostname sshd[1234]: Failed password for john from 192.168.1.1
    const regex = /(\w+ \d+ \d+:\d+:\d+) (\S+) (\S+)\[(\d+)\]: (.+)/;
    const match = line.match(regex);
    
    if (!match) throw new Error('Could not parse syslog');

    const isAuthFailure = match[5].includes('Failed password') || match[5].includes('Invalid user');

    return {
      event_type: isAuthFailure ? 'auth_failure' : 'system_event',
      timestamp: new Date(match[1]).toISOString(),
      hostname: match[2],
      service: match[3],
      pid: match[4],
      message: match[5],
      source_ip: this._extractIP(match[5]),
      user: this._extractUser(match[5]),
      raw: line
    };
  }

  _extractIP(str) {
    const match = str.match(/(\d+\.\d+\.\d+\.\d+)/);
    return match ? match[1] : null;
  }

  _extractUser(str) {
    const match = str.match(/user (\S+)|for (\S+)/);
    return match ? (match[1] || match[2]) : null;
  }
}

module.exports = LogParser;
```

### 3.5 Security Handler

```javascript
// backend/agent/src/security/securityHandler.js
const crypto = require('crypto');

class SecurityHandler {
  constructor(config) {
    this.apiKey = config.organization.api_key;
  }

  signPayload(payload) {
    const timestamp = Math.floor(Date.now() / 1000);
    const payloadStr = JSON.stringify(payload);
    const payloadHash = crypto.createHash('sha256').update(payloadStr).digest('hex');
    
    const message = `${payloadHash}.${timestamp}`;
    const signature = crypto
      .createHmac('sha256', this.apiKey)
      .update(message)
      .digest('hex');

    return { signature, timestamp };
  }
}

module.exports = SecurityHandler;
```

### 3.6 Event Buffer

```javascript
// backend/agent/src/buffer/eventBuffer.js
class EventBuffer {
  constructor(maxSize, batchSize) {
    this.maxSize = maxSize;
    this.batchSize = batchSize;
    this.buffer = [];
    this.droppedCount = 0;
  }

  push(event) {
    if (this.buffer.length >= this.maxSize) {
      this.droppedCount++;
      if (this.droppedCount % 100 === 0) {
        console.warn(`[Buffer] Dropped ${this.droppedCount} events (buffer full)`);
      }
      return false;
    }

    this.buffer.push(event);
    return true;
  }

  getBatch() {
    const batch = this.buffer.splice(0, this.batchSize);
    return batch;
  }

  requeue(events) {
    this.buffer.unshift(...events);
  }

  size() {
    return this.buffer.length;
  }
}

module.exports = EventBuffer;
```

---

## Priority 4: Real Detection Engine

### 4.1 Restructure IDS Engine

Currently your `ids-engine/` has simulated detection. Replace it with real detection:

```python
# backend/ids-engine/app.py
from flask import Flask, jsonify
from detectors import BruteForceDetector, DDosDetector, InjectionDetector
from queue_service import consume_events
from logger import get_logger

app = Flask(__name__)
logger = get_logger('ids-engine')

brute_force_detector = BruteForceDetector()
ddos_detector = DDosDetector()
injection_detector = InjectionDetector()

@app.route('/health', methods=['GET'])
def health():
    return jsonify({ 'status': 'ok' })

def start_detection_worker():
    """Consume events from queue and run detectors"""
    while True:
        events = consume_events('inbound:events', batch_size=100)
        
        alerts = []
        for event in events:
            # Run all detectors
            alerts.extend(brute_force_detector.detect([event]))
            alerts.extend(ddos_detector.detect([event]))
            alerts.extend(injection_detector.detect([event]))
        
        # Publish alerts to output queue
        for alert in alerts:
            publish_alert('outbound:alerts', alert)
        
        logger.info(f'Processed {len(events)} events, generated {len(alerts)} alerts')

if __name__ == '__main__':
    from threading import Thread
    
    # Start detection worker in background
    detection_thread = Thread(target=start_detection_worker, daemon=True)
    detection_thread.start()
    
    # Start Flask API
    app.run(port=5001, debug=False)
```

### 4.2 Create Real Detectors

```python
# backend/ids-engine/detectors/bruteforce.py
from datetime import datetime, timedelta

class BruteForceDetector:
    def __init__(self):
        self.ip_failures = {}  # IP -> [timestamps]
        self.user_failures = {}  # user -> [timestamps]
    
    def detect(self, events):
        alerts = []
        
        for event in events:
            if event.get('event_type') != 'auth_failure':
                continue
            
            ip = event.get('source_ip')
            user = event.get('user')
            now = datetime.fromisoformat(event.get('timestamp'))
            
            # Track per-IP failures
            if ip not in self.ip_failures:
                self.ip_failures[ip] = []
            
            self.ip_failures[ip].append(now)
            
            # Clean old entries (> 5min)
            cutoff = now - timedelta(minutes=5)
            self.ip_failures[ip] = [t for t in self.ip_failures[ip] if t > cutoff]
            
            # Alert if >10 failures in 5min
            if len(self.ip_failures[ip]) >= 10:
                alerts.append({
                    'alert_id': str(uuid.uuid4()),
                    'timestamp': now.isoformat(),
                    'alert_type': 'brute_force_attack',
                    'severity': 'high',
                    'confidence': 0.95,
                    'source_ip': ip,
                    'failed_attempts': len(self.ip_failures[ip]),
                    'description': f'Brute force attempt from {ip}',
                })
        
        return alerts
```

Continue with DDos and Injection detectors...

---

## Priority 5: Message Queue Setup

### 5.1 Redis Queue (Simple Option)

```javascript
// backend/api-server/services/queue.service.js
const redis = require('redis');

class QueueService {
  constructor() {
    this.client = redis.createClient({
      host: process.env.REDIS_HOST || 'localhost',
      port: process.env.REDIS_PORT || 6379,
    });
    this.client.connect();
  }

  async publish(channel, message) {
    await this.client.publish(channel, message);
  }

  async subscribe(channel, callback) {
    const subscriber = this.client.duplicate();
    await subscriber.connect();
    await subscriber.subscribe(channel, (message) => {
      callback(JSON.parse(message));
    });
  }
}

module.exports = new QueueService();
```

### 5.2 Update Ingest to Queue Events

```javascript
// In ingest.controller.js
const Queue = require('../services/queue.service');

for (const event of enrichedEvents) {
  await Queue.publish('inbound:events', JSON.stringify(event));
}
```

---

## Priority 6: Update Existing Routes (Add Org Filtering)

### 6.1 Alerts Route

```javascript
// backend/api-server/routes/alerts.routes.js - UPDATED for multi-tenant

router.get('/', async (req, res) => {
  const { orgId } = req; // From middleware
  const { status, severity, page = 1, limit = 20 } = req.query;

  const filter = { _org_id: orgId }; // ← CRITICAL

  if (status) filter.status = status;
  if (severity) filter.severity = severity;

  const alerts = await Alert.find(filter)
    .sort({ created_at: -1 })
    .skip((page - 1) * limit)
    .limit(limit);

  res.json({ alerts, total: await Alert.countDocuments(filter) });
});
```

Do the same for:
- `/api/logs` → Filter by `_org_id`
- `/api/dashboard/stats` → Filter by `_org_id`
- `/api/assets` → Filter by `_org_id`

---

## Quick Checklist: What Changes Right Now

### Phase 1 (This Week)
- [ ] Add `_org_id` field to all models
- [ ] Create Organization model
- [ ] Create APIKey model
- [ ] Update all route handlers to filter by `_org_id`
- [ ] Create ingest API endpoints
- [ ] Create ingest middleware (API key validation)

### Phase 2 (Next Week)
- [ ] Build ThreatLens Agent
- [ ] Test agent → API communication
- [ ] Deploy Redis queue
- [ ] Queue events from ingest API

### Phase 3 (Week After)
- [ ] Implement real detection engine (rule-based)
- [ ] Setup PythonChecker detection workers
- [ ] Test end-to-end: agent → ingest → detection → alert

---

## Testing the Integration

### Agent Test

```bash
# 1. Create test API key
curl -X POST http://localhost:3000/api/admin/api-keys \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": "test-asset-001",
    "name": "Test Agent Key"
  }'

# Response: { "api_key": "tlk_org123_abc123..." }

# 2. Configure agent
cp backend/agent/config.example.json backend/agent/config.json
# Edit config.json with the API key

# 3. Run agent
node backend/agent/src/agent.js backend/agent/config.json

# 4. Check ingestion API logs
# Should see: "[Ingest] 500 events from org org_123456"
```

---

## What NOT to Do

❌ **DON'T** skip multi-tenant isolation - add it from the start  
❌ **DON'T** build agent as full IDS - it's just a collector  
❌ **DON'T** store raw payloads - hash them for privacy  
❌ **DON'T** use plaintext for API key secret - hash it  
❌ **DON'T** assume all agents send perfect data - validate & normalize  

---

## Success Criteria

✅ Agent can send events securely to API  
✅ API validates API keys and HMAC signatures  
✅ All data queries include `_org_id` filter  
✅ Org A cannot access Org B's data  
✅ Real detection engine analyzes actual events (not simulated)  
✅ Alerts are generated from real agent data  
✅ Dashboard shows real incidents  

---

## Next Steps

1. **Start with Priority 1** (Multi-tenant): This foundation is critical
2. **Then Priority 2** (Ingestion API): Secure the entry point
3. **Then Priority 3** (Agent): Build the data source
4. **Then Priority 4** (Detection): Move from simulator to real detection
5. **Then Priority 5** (Queue): Add async processing
6. **Then Priority 6** (Updates): Retrofit existing routes

That's your roadmap to a production-grade IDS.
