import random

PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "SSH"]
ENDPOINTS = ["/api/auth/login", "/api/logs", "/api/alerts", "/admin/users", "/reports/export"]


def _single_sample():
    port = random.choice([22, 53, 80, 443, 445, 8080, 3306, 3389])
    protocol = "SSH" if port == 22 else "HTTPS" if port == 443 else "HTTP" if port in [80, 8080] else random.choice(PROTOCOLS)
    packets = random.randint(10, 520)
    failed_attempts = random.randint(0, 10)
    flow_count = random.randint(1, 28)
    return {
        "ip": "192.168.1." + str(random.randint(1, 255)),
        "packets": packets,
        "port": port,
        "protocol": protocol,
        "bytes": random.randint(1200, 98000),
        "duration": round(random.uniform(0.4, 18.0), 2),
        "request_rate": random.randint(5, 220),
        "failed_attempts": failed_attempts,
        "flags": random.sample(["SYN", "ACK", "PSH", "FIN", "RST"], k=2)
        if protocol != "UDP"
        else ["NONE", "NONE"],
        "flow_count": flow_count,
        "unique_ports": random.randint(1, 20),
        "dns_queries": random.randint(0, 120) if port == 53 else 0,
        "smb_writes": random.randint(0, 40) if port == 445 else 0,
        "endpoint": random.choice(ENDPOINTS)
    }


def generate_traffic(samples=1):
    if samples <= 1:
        return _single_sample()

    return [_single_sample() for _ in range(samples)]
