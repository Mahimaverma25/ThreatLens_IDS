import random
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Union

PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "SSH", "DNS", "SMB"]
ENDPOINTS = [
    "/api/auth/login",
    "/api/logs",
    "/api/alerts",
    "/admin/users",
    "/reports/export",
    "/upload",
    "/dashboard",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _random_ip(private: bool = True) -> str:
    if private:
        return f"192.168.1.{random.randint(2, 254)}"

    return f"{random.randint(11, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _protocol_from_port(port: int) -> str:
    mapping = {
        22: "SSH",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        445: "SMB",
        8080: "HTTP",
        3306: "TCP",
        3389: "TCP",
    }

    return mapping.get(port, random.choice(PROTOCOLS))


def _base_sample() -> Dict:
    port = random.choice([22, 53, 80, 443, 445, 8080, 3306, 3389])
    protocol = _protocol_from_port(port)

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": _now_iso(),

        "src_ip": _random_ip(private=False),
        "dest_ip": _random_ip(private=True),

        "src_port": random.randint(1024, 65535),
        "dest_port": port,
        "port": port,

        "protocol": protocol,
        "event_type": "simulated_network_flow",
        "source": "traffic_simulator",

        "packets": random.randint(10, 180),
        "bytes": random.randint(1200, 45000),
        "duration": round(random.uniform(0.4, 8.0), 2),
        "request_rate": random.randint(5, 90),
        "failed_attempts": random.randint(0, 3),

        "flow_count": random.randint(1, 10),
        "unique_ports": random.randint(1, 6),
        "dns_queries": random.randint(0, 20) if port == 53 else 0,
        "smb_writes": random.randint(0, 8) if port == 445 else 0,

        "flags": random.sample(["SYN", "ACK", "PSH", "FIN", "RST"], k=2)
        if protocol != "UDP"
        else ["NONE", "NONE"],

        "endpoint": random.choice(ENDPOINTS),
        "snort_priority": 0,
        "is_snort": 0,
    }


def _ddos_sample() -> Dict:
    sample = _base_sample()
    sample.update({
        "dest_port": random.choice([80, 443, 8080]),
        "port": sample["dest_port"],
        "protocol": "HTTP" if sample["dest_port"] != 443 else "HTTPS",
        "packets": random.randint(330, 650),
        "bytes": random.randint(50000, 160000),
        "request_rate": random.randint(250, 480),
        "flow_count": random.randint(20, 45),
        "unique_ports": random.randint(4, 10),
        "attack_type": "Possible DDoS Attack",
        "snort_priority": 1,
        "is_snort": 1,
    })
    return sample


def _bruteforce_sample() -> Dict:
    sample = _base_sample()
    sample.update({
        "dest_port": 22,
        "port": 22,
        "protocol": "SSH",
        "packets": random.randint(120, 260),
        "bytes": random.randint(8000, 30000),
        "request_rate": random.randint(50, 140),
        "failed_attempts": random.randint(7, 18),
        "flow_count": random.randint(10, 24),
        "attack_type": "Brute Force SSH Attempt",
        "snort_priority": 2,
        "is_snort": 1,
    })
    return sample


def _port_scan_sample() -> Dict:
    sample = _base_sample()
    sample.update({
        "protocol": "TCP",
        "packets": random.randint(145, 260),
        "bytes": random.randint(8000, 28000),
        "request_rate": random.randint(60, 160),
        "flow_count": random.randint(18, 36),
        "unique_ports": random.randint(12, 30),
        "attack_type": "Port Scan Activity",
        "snort_priority": 2,
        "is_snort": 1,
    })
    return sample


def _dns_tunnel_sample() -> Dict:
    sample = _base_sample()
    sample.update({
        "dest_port": 53,
        "port": 53,
        "protocol": "UDP",
        "packets": random.randint(120, 260),
        "bytes": random.randint(16000, 50000),
        "request_rate": random.randint(80, 180),
        "dns_queries": random.randint(110, 220),
        "flow_count": random.randint(14, 28),
        "unique_ports": random.randint(6, 14),
        "attack_type": "DNS Tunneling / Covert Channel",
        "snort_priority": 2,
        "is_snort": 1,
    })
    return sample


def _exfiltration_sample() -> Dict:
    sample = _base_sample()
    sample.update({
        "dest_port": 443,
        "port": 443,
        "protocol": "HTTPS",
        "packets": random.randint(160, 320),
        "bytes": random.randint(95000, 250000),
        "request_rate": random.randint(45, 110),
        "flow_count": random.randint(14, 32),
        "unique_ports": random.randint(2, 8),
        "attack_type": "Potential Data Exfiltration",
        "snort_priority": 1,
        "is_snort": 1,
    })
    return sample


def _smb_lateral_sample() -> Dict:
    sample = _base_sample()
    sample.update({
        "dest_port": 445,
        "port": 445,
        "protocol": "SMB",
        "packets": random.randint(120, 260),
        "bytes": random.randint(30000, 100000),
        "request_rate": random.randint(25, 90),
        "flow_count": random.randint(12, 28),
        "smb_writes": random.randint(25, 60),
        "attack_type": "Suspicious SMB Lateral Movement",
        "snort_priority": 1,
        "is_snort": 1,
    })
    return sample


def _web_attack_sample() -> Dict:
    sample = _base_sample()
    sample.update({
        "dest_port": random.choice([80, 443, 8080]),
        "port": sample["dest_port"],
        "protocol": "HTTPS" if sample["dest_port"] == 443 else "HTTP",
        "packets": random.randint(120, 280),
        "bytes": random.randint(10000, 70000),
        "request_rate": random.randint(75, 190),
        "failed_attempts": random.randint(4, 14),
        "flow_count": random.randint(10, 24),
        "endpoint": random.choice(["/login", "/search?q=' OR 1=1", "/admin", "/api/auth/login"]),
        "attack_type": "Web Exploitation / SQLi Probe",
        "snort_priority": 2,
        "is_snort": 1,
    })
    return sample


def _single_sample(profile: str = "mixed") -> Dict:
    profile = str(profile or "mixed").lower()

    generators = {
        "benign": _base_sample,
        "ddos": _ddos_sample,
        "bruteforce": _bruteforce_sample,
        "port_scan": _port_scan_sample,
        "scan": _port_scan_sample,
        "dns_tunnel": _dns_tunnel_sample,
        "exfiltration": _exfiltration_sample,
        "smb": _smb_lateral_sample,
        "web": _web_attack_sample,
        "sqli": _web_attack_sample,
    }

    if profile in generators:
        return generators[profile]()

    weighted_profiles = [
        _base_sample,
        _base_sample,
        _base_sample,
        _ddos_sample,
        _bruteforce_sample,
        _port_scan_sample,
        _dns_tunnel_sample,
        _exfiltration_sample,
        _smb_lateral_sample,
        _web_attack_sample,
    ]

    return random.choice(weighted_profiles)()


def generate_traffic(samples: int = 1, profile: str = "mixed") -> Union[Dict, List[Dict]]:
    """
    Generate simulated ThreatLens traffic.

    profile options:
    benign, ddos, bruteforce, port_scan, dns_tunnel,
    exfiltration, smb, web, mixed
    """

    samples = int(samples or 1)

    if samples <= 1:
        return _single_sample(profile)

    return [_single_sample(profile) for _ in range(samples)]