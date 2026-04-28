import time
from typing import List, Dict

from detector.pipeline import detect_event
from utils.logger import get_logger

logger = get_logger("ids-engine.stream")


class StreamProcessor:
    def __init__(self, batch_size: int = 10, flush_interval: int = 5):
        self.batch_size = batch_size
        self.flush_interval = flush_interval

        self.buffer: List[Dict] = []
        self.last_flush = time.time()

    def add_event(self, event: Dict):
        """
        Add incoming event to buffer
        """

        self.buffer.append(event)

        if len(self.buffer) >= self.batch_size:
            self.flush()

        elif time.time() - self.last_flush >= self.flush_interval:
            self.flush()

    def flush(self):
        """
        Process buffered events
        """

        if not self.buffer:
            return

        logger.info(f"Processing {len(self.buffer)} events")

        results = []

        for event in self.buffer:
            try:
                result = detect_event(event)
                results.append(result)

            except Exception as e:
                logger.error(f"Stream processing error: {e}")

        # Clear buffer
        self.buffer = []
        self.last_flush = time.time()

        return results


# ---------- SIMPLE REAL-TIME PROCESSOR ----------

def process_stream(events: List[Dict]):
    """
    One-time batch processing (for testing or CSV upload)
    """

    results = []

    for event in events:
        try:
            result = detect_event(event)
            results.append(result)
        except Exception as e:
            logger.error(f"Processing failed: {e}")

    return results