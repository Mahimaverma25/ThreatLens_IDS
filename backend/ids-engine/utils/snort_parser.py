import re
from datetime import datetime

SNORT_REGEX = re.compile(
    r'(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<msg>.*?)\s+\[\*\*\]\s+\[Priority:\s*(?P<priority>\d+)\]\s+\{(?P<protocol>\w+)\}\s+(?P<src_ip>[\d\.]+):(?P<src_port>\d+)\s+->\s+(?P<dest_ip>[\d\.]+):(?P<dest_port>\d+)'
)

def parse_snort_log(log_line):
    try:
        match = SNORT_REGEX.search(log_line)

        if not match:
            return None  # skip invalid lines

        data = match.groupdict()

        # Convert timestamp to ISO format
        timestamp = datetime.strptime(data["timestamp"], "%m/%d-%H:%M:%S.%f")
        
        return {
            "timestamp": timestamp.isoformat(),

            # Network Info
            "src_ip": data["src_ip"],
            "src_port": int(data["src_port"]),
            "dest_ip": data["dest_ip"],
            "dest_port": int(data["dest_port"]),
            "protocol": data["protocol"],

            # Attack Info
            "attack_type": data["msg"],
            "signature_id": int(data["sid"]),
            "gid": int(data["gid"]),
            "revision": int(data["rev"]),
            "priority": int(data["priority"]),

            # ThreatLens Standard Fields
            "event_type": "network_intrusion",
            "severity": map_priority_to_severity(int(data["priority"])),

            # Raw log (important for debugging)
            "raw_log": log_line.strip()
        }

    except Exception as e:
        print(f"[Snort Parser Error] {e}")
        return None


def map_priority_to_severity(priority):
    if priority == 1:
        return "critical"
    elif priority == 2:
        return "high"
    elif priority == 3:
        return "medium"
    else:
        return "low"