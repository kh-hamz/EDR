import logging
import threading

import requests

from ..buffer.disk_queue import DiskQueue
from ..config import AgentSettings

log = logging.getLogger(__name__)

MAX_BACKOFF = 60.0


class HttpShipper:
    def __init__(self, settings: AgentSettings, queue: DiskQueue):
        self.settings = settings
        self.queue = queue
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {settings.api_token}"

    def run(self, stop: threading.Event) -> None:
        backoff = 1.0
        url = f"{self.settings.backend_url}/ingest"
        while not stop.is_set():
            items, cursor = self.queue.read_batch(self.settings.batch_size)
            if not items:
                stop.wait(self.settings.flush_interval)
                continue
            try:
                resp = self.session.post(url, json=items, timeout=15)
                resp.raise_for_status()
                self.queue.commit(cursor)
                backoff = 1.0
                log.debug("shipped %d events", len(items))
            except requests.RequestException as exc:
                log.warning("ship failed (%s), retrying in %.0fs", exc, backoff)
                stop.wait(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF)
