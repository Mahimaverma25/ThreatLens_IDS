
# ThreatLens Agent

A lightweight Node.js agent for collecting and forwarding security events to the ThreatLens backend.

## Features
- Collects system, network, and application events
- Secure API key authentication (HMAC signing supported)
- Batching and retry logic for reliability
- Configurable log sources and monitored ports

## Folder Structure
```
agent/
   agent.js
   agent-data/
   package.json
   README.md
```

## Setup & Run
1. Copy `.env.example` to `.env` and fill in your API credentials and asset ID.
2. Install dependencies:
  ```bash
  cd backend/agent
  npm install
  ```
3. Start the agent:
  ```bash
  npm start
  ```

## Configuration
Edit `.env` with:
- `THREATLENS_API_URL` — Backend API URL
- `THREATLENS_API_KEY` — API key from dashboard
- `THREATLENS_API_SECRET` — API secret (if used)
- `ASSET_ID` — Unique asset identifier

## Security
- API key is required for all submissions
- HMAC signing is recommended for production

## Troubleshooting
- Check logs in `agent-error.log` for issues
- Ensure API key and asset ID are correct
- Network errors may indicate backend is unreachable

## Integration
- Designed to work with ThreatLens backend and dashboard
- Can be extended to support additional log sources
6. Add credentials to `.env` file on the Agent host

## Security Best Practices

### Credential Management

```bash
# Use environment variables instead of .env for production
export THREATLENS_API_KEY="your-key"
export THREATLENS_API_SECRET="your-secret"
export ASSET_ID="asset-id"

node agent.js
```

### Network Security

- Always use HTTPS for API_URL in production
- Implement firewall rules to restrict agent outbound connections
- Use VPN or private networks where possible
- Rotate API secrets regularly

### File Permissions

```bash
# Restrict permissions on .env file
chmod 600 .env

# Restrict permissions on log files
chmod 700 agent-data/
```

## Event Types

The agent collects the following event types:

### System Events
- **auth_success**: Successful user authentication
- **auth_failure**: Failed authentication attempt
- **sudo_attempt**: Sudo command execution
- **ssh_login**: SSH login activity

### HTTP Events
- **http_request**: API/web request with status codes
- **http_error**: 4xx/5xx responses
- **api_call**: API endpoint access

### Network Events
- **network_connection**: Inbound/outbound connections
- **port_scan**: Port scanning detection
- **dns_query**: DNS resolution attempts

### File Events
- **file_access**: File read/write/delete operations
- **permission_change**: File permission modifications
- **configuration_change**: Config file modifications

## Event Format

Each event includes:

```json
{
  "event_id": "asset-12345-1699000000000",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "event_type": "http_request",
  "severity": "low",
  "source": "http",
  "asset_id": "asset-web01",
  "metadata": {
    "method": "GET",
    "path": "/api/users",
    "status_code": 200,
    "source_ip": "203.0.113.45",
    "response_time_ms": 125
  }
}
```

## Monitoring Agent Health

### Check Agent Status

```bash
# View the agent logs
tail -f agent-combined.log

# Check if agent is running
ps aux | grep agent.js

# View buffered events stats
grep "Buffered events" agent-combined.log
```

### Event Submission Logs

```bash
# View successful submissions
grep "Successfully submitted" agent-combined.log

# View failed submissions
grep "Failed to submit" agent-error.log

# View retry attempts
grep "Retry" agent-combined.log
```

### Health Check

The agent performs periodic health checks (default: every 60s):

```bash
# View health check results
grep "Health check" agent-combined.log

# View statistics retrieval
grep "Agent stats" agent-combined.log
```

## Troubleshooting

### Agent Not Starting

```bash
# Check Node.js version
node --version  # Should be 18+

# Check dependencies
npm install

# Run with debug logging
LOG_LEVEL=debug node agent.js
```

### Events Not Being Sent

```bash
# Verify API credentials
grep "API URL\|Asset ID" agent-combined.log

# Check connectivity to API
curl -v http://your-api-url/api/ingest/v1/health

# Verify HMAC signature generation
LOG_LEVEL=debug node agent.js
```

### High Memory Usage

- Reduce `BATCH_SIZE` to flush events more frequently
- Reduce `BATCH_TIMEOUT_MS` to send batches sooner
- Check for event collection loops that aren't terminating

## Performance Tuning

### For High-Volume Environments

```bash
# Increase batch size for fewer API calls
BATCH_SIZE=500

# Longer timeout before flushing
BATCH_TIMEOUT_MS=30000

# Longer health check interval
HEALTH_CHECK_INTERVAL_MS=300000
```

### For Low-Latency Alerts

```bash
# Smaller batch size for faster detection
BATCH_SIZE=10

# Quick timeout to send alerts immediately
BATCH_TIMEOUT_MS=1000
```

## Production Deployment

### Systemd Service

```ini
# /etc/systemd/system/threatLens-agent.service
[Unit]
Description=ThreatLens Security Agent
After=network.target

[Service]
Type=simple
User=threatLens
WorkingDirectory=/opt/threatLens-agent
EnvironmentFile=/opt/threatLens-agent/.env
ExecStart=/usr/bin/node /opt/threatLens-agent/agent.js
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable threatLens-agent
sudo systemctl start threatLens-agent
sudo systemctl status threatLens-agent
```

### Docker Compose

```yaml
version: '3.8'
services:
  threatLens-agent:
    build: .
    environment:
      THREATLENS_API_URL: http://threatLens-api:3000
      THREATLENS_API_KEY: ${API_KEY}
      THREATLENS_API_SECRET: ${API_SECRET}
      ASSET_ID: ${ASSET_ID}
    restart: unless-stopped
    volumes:
      - ./agent-data:/app/agent-data
      - /var/log:/var/log:ro
```

## Support

For issues, questions, or feature requests:

1. Check logs for error messages
2. Review configuration in `.env`
3. Verify API credentials are correct
4. Check connectivity to API server
5. Contact ThreatLens support with agent logs

## License

MIT

---

**ThreatLens Agent** - Secure. Scalable. Simple.
