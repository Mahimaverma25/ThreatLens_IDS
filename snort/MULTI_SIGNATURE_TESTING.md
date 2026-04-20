# ThreatLens Multi-Signature Snort Testing

Use these rules to generate multiple real Snort signatures for the ThreatLens dashboard,
logs page, alert pipeline, and ML-assisted detections.

Rules file:

- [snort/threatlens-local.rules](/D:/Major%20Project/ThreatLens/snort/threatlens-local.rules)

## 1. Load the rules into Snort

Append or copy the rules into your active `local.rules`, then ensure your Snort config includes that file.

Example include in `snort.conf`:

```conf
include $RULE_PATH/local.rules
```

If you want to keep them separate, include this file directly:

```conf
include /mnt/d/Major\ Project/ThreatLens/snort/threatlens-local.rules
```

Or copy it into your Snort rules directory:

```bash
sudo cp /mnt/d/Major\ Project/ThreatLens/snort/threatlens-local.rules /etc/snort/rules/local.rules
```

## 2. Restart Snort

Restart Snort after updating the rules so the new signatures are active.

## 3. Trigger different signatures

ICMP:

```bash
ping -c 2 127.0.0.1
```

HTTP admin path:

```bash
curl "http://127.0.0.1/admin"
```

SQL injection test:

```bash
curl "http://127.0.0.1/search?q=union%20select"
```

XSS test:

```bash
curl "http://127.0.0.1/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

Directory traversal test:

```bash
curl "http://127.0.0.1/download?file=../../etc/passwd"
```

RCE-style probe:

```bash
curl "http://127.0.0.1/run?cmd=whoami"
```

SSH probe:

```bash
nc -vz 127.0.0.1 22
```

FTP anonymous probe:

```bash
printf 'USER anonymous\r\n' | nc 127.0.0.1 21
```

Telnet probe:

```bash
nc -vz 127.0.0.1 23
```

SMB probe:

```bash
nc -vz 127.0.0.1 445
```

RDP probe:

```bash
nc -vz 127.0.0.1 3389
```

DNS tunnel keyword:

```bash
printf 'threatlens-tunnel' | nc -u -w1 127.0.0.1 53
```

LDAP probe:

```bash
nc -vz 127.0.0.1 389
```

SMTP probe:

```bash
printf 'HELO test\r\nRCPT TO:test@example.com\r\n' | nc 127.0.0.1 25
```

Beacon keyword test:

```bash
printf 'beacon' | nc 127.0.0.1 443
```

NTP amplification pattern test:

```bash
printf '\x17\x00\x03\x2a' | nc -u -w1 127.0.0.1 123
```

## 4. Verify ThreatLens

Keep the ThreatLens agent running, then confirm:

- `backend/agent` logs show `Snort event buffered`
- the dashboard shows multiple signatures
- the logs page shows different classifications and ports

## Expected signatures

- `ThreatLens ICMP Echo Activity`
- `ThreatLens HTTP Admin Access Probe`
- `ThreatLens SQL Injection Probe`
- `ThreatLens XSS Attempt Probe`
- `ThreatLens Directory Traversal Probe`
- `ThreatLens Remote Code Execution Probe`
- `ThreatLens SSH Access Probe`
- `ThreatLens SMB Lateral Movement Probe`
- `ThreatLens DNS Tunnel Keyword`
- `ThreatLens RDP Burst Probe`
- `ThreatLens FTP Anonymous Login Probe`
- `ThreatLens Telnet Exposure Probe`
- `ThreatLens NTP Amplification Probe`
- `ThreatLens LDAP Enumeration Probe`
- `ThreatLens Suspicious SMTP Relay Probe`
- `ThreatLens Malware Beacon Keyword`

## Notes

- If your Snort deployment monitors a different interface/host than `127.0.0.1`, replace the destination IP in the test commands.
- If `nc` is not installed, use `nmap -Pn -p 22,445,3389 127.0.0.1` for the TCP probe signatures.
- These are test signatures for dashboard verification, not production-quality detection rules.
- If your Snort build is strict about HTTP inspection or encrypted HTTPS traffic, some web-content rules are easiest to test against plain HTTP on port `80` or `8080`.
- After updating the rules, restart Snort and keep the ThreatLens agent running so the events flow into MongoDB and the dashboard in real time.
