import random

PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "SSH"]


def _single_sample():
    port = random.choice([22, 80, 443, 8080])
    protocol = "SSH" if port == 22 else "HTTPS" if port == 443 else "HTTP" if port in [80, 8080] else random.choice(PROTOCOLS)
    return {
        "ip": "192.168.1." + str(random.randint(1, 255)),
        "packets": random.randint(10, 500),
        "port": port,
        "protocol": protocol,
        "bytes": random.randint(1200, 98000),
        "duration": round(random.uniform(0.4, 18.0), 2),
        "request_rate": random.randint(5, 220),
        "failed_attempts": random.randint(0, 8),
        "flags": random.sample(["SYN", "ACK", "PSH", "FIN", "RST"], k=2)
    }


def generate_traffic(samples=1):
    if samples <= 1:
        return _single_sample()

    return [_single_sample() for _ in range(samples)]
