"""Agent orchestration: collector threads -> normalizer -> disk buffer -> shipper."""

import logging
import signal
import threading

from .buffer.disk_queue import DiskQueue
from .collectors.base import Collector
from .collectors.falco_collector import FalcoCollector
from .collectors.osquery_collector import OsqueryCollector
from .config import AgentSettings
from .enrollment import ensure_enrolled
from .normalizer.ocsf_mapper import normalize
from .responder.poller import Responder
from .transport.http_shipper import HttpShipper

log = logging.getLogger(__name__)


class EDRAgent:
    def __init__(self, settings: AgentSettings):
        self.settings = settings
        self.stop = threading.Event()

    def run(self) -> int:
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        enrolled = ensure_enrolled(self.settings, self.stop)
        if enrolled is None:
            return 1
        self.agent_id, self.host = enrolled

        queue = DiskQueue(self.settings.spool_dir)
        collectors: list[Collector] = [
            FalcoCollector(self.settings.falco_log),
            OsqueryCollector(self.settings.osquery_log),
        ]
        shipper = HttpShipper(self.settings, queue)
        responder = Responder(self.settings, self.agent_id)

        threads = [
            threading.Thread(target=self._collect, args=(c, queue), name=c.observer, daemon=True)
            for c in collectors
        ]
        threads.append(threading.Thread(target=shipper.run, args=(self.stop,), name="shipper", daemon=True))
        threads.append(threading.Thread(target=responder.run, args=(self.stop,), name="responder", daemon=True))
        for t in threads:
            t.start()

        log.info("agent running (agent_id=%s, host=%s)", self.agent_id, self.host.hostname)
        self.stop.wait()
        for t in threads:
            t.join(timeout=5)
        log.info("agent stopped")
        return 0

    def _collect(self, collector: Collector, queue: DiskQueue) -> None:
        for raw in collector.stream(self.stop):
            for event in normalize(raw, collector.observer, self.agent_id, self.host):
                queue.put(event.model_dump(mode="json"))

    def _handle_signal(self, signum, frame) -> None:
        log.info("received signal %d, shutting down", signum)
        self.stop.set()
