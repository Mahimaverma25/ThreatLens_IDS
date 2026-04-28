import time
import requests
import os
import hashlib
import hmac
import json

from utils.logger import get_logger

logger = get_logger("ids-engine.api-client")

API_URL = os.getenv("THREATLENS_API_URL", "http://localhost:5000/api/alerts")
API_KEY = os.getenv("THREATLENS_API_KEY", "test-key")
API_SECRET = os.getenv("THREATLENS_API_SECRET", "test-secret")

TIMEOUT = 5
MAX_RETRIES = 3


# ---------- SIGNATURE (SECURITY) ----------

def generate_signature(payload: dict, timestamp: str) -> str:
    """
    HMAC SHA256 signature
    """
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    message = f"{timestamp}.{body}".encode()

    secret = hashlib.sha256(API_SECRET.encode()).digest()
    signature = hmac.new(secret, message, hashlib.sha256).hexdigest()

    return signature


# ---------- SEND ALERT ----------

def send_alert(data: dict) -> bool:
    """
    Sends alert to backend with retry + security
    """

    timestamp = str(int(time.time()))

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
        "X-Timestamp": timestamp,
        "X-Signature": generate_signature(data, timestamp),
    }

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.post(
                API_URL,
                json=data,
                headers=headers,
                timeout=TIMEOUT
            )

            if response.status_code in (200, 201):
                logger.info("Alert sent successfully")
                return True

            logger.warning(
                f"Failed to send alert (status={response.status_code}): {response.text}"
            )

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout while sending alert (attempt {attempt})")

        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error (attempt {attempt})")

        except Exception as e:
            logger.error(f"Unexpected error: {e}")

        # Retry delay (exponential backoff)
        time.sleep(2 ** attempt)

    logger.error("Failed to send alert after retries")
    return False


# ---------- OPTIONAL: BATCH ALERTS ----------

def send_alert_batch(alerts: list):
    """
    Send multiple alerts efficiently
    """

    success = 0

    for alert in alerts:
        if send_alert(alert):
            success += 1

    logger.info(f"Batch send complete: {success}/{len(alerts)} successful")