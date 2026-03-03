import random


def _single_sample():
    return {
        "ip": "192.168.1." + str(random.randint(1, 255)),
        "packets": random.randint(10, 500),
        "port": random.choice([22, 80, 443, 8080])
    }


def generate_traffic(samples=1):
    if samples <= 1:
        return _single_sample()

    return [_single_sample() for _ in range(samples)]
