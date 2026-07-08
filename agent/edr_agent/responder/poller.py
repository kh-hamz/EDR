"""Polls the backend for pending commands, runs them, and acks the result.

Runs as its own thread alongside the collectors and shipper. A poll failure
(backend down) is logged and retried on the next interval - commands stay
pending server-side, so nothing is lost while the backend is unreachable.
"""

import logging
import threading
from urllib.parse import urlparse

import requests

from ..config import AgentSettings
from . import actions

log = logging.getLogger(__name__)


class Responder:
    def __init__(self, settings: AgentSettings, agent_id: str):
        self.settings = settings
        self.agent_id = agent_id
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {settings.api_token}"
        # Backend host stays reachable during isolation so unisolate can arrive.
        self._backend_host = urlparse(settings.backend_url).hostname or "127.0.0.1"
        self._quarantine_dir = f"{settings.data_dir}/quarantine"

    def run(self, stop: threading.Event) -> None:
        url = f"{self.settings.backend_url}/response/commands"
        while not stop.is_set():
            try:
                resp = self.session.get(url, params={"agent_id": self.agent_id}, timeout=10)
                resp.raise_for_status()
                commands = resp.json()
            except requests.RequestException as exc:
                log.warning("command poll failed (%s)", exc)
                stop.wait(self.settings.command_poll_interval)
                continue

            for command in commands:
                self._handle(command)

            stop.wait(self.settings.command_poll_interval)

    def _handle(self, command: dict) -> None:
        command_id = command["id"]
        try:
            result = self._execute(command["action"], command.get("params") or {})
            status = "succeeded"
            log.info("command %d (%s) succeeded: %s", command_id, command["action"], result)
        except actions.ActionFailed as exc:
            result, status = str(exc), "failed"
            log.warning("command %d (%s) failed: %s", command_id, command["action"], exc)
        except Exception as exc:  # unknown action, bad params, unexpected error
            result, status = f"error: {exc}", "failed"
            log.exception("command %d (%s) errored", command_id, command["action"])
        self._ack(command_id, status, result)

    def _execute(self, action: str, params: dict) -> str:
        if action == "kill_process":
            return actions.kill_process(int(params["pid"]))
        if action == "isolate_host":
            return actions.isolate_host(self._backend_host)
        if action == "unisolate_host":
            return actions.unisolate_host()
        if action == "quarantine_file":
            return actions.quarantine_file(params["path"], self._quarantine_dir)
        raise ValueError(f"unknown action '{action}'")

    def _ack(self, command_id: int, status: str, result: str) -> None:
        url = f"{self.settings.backend_url}/response/commands/{command_id}/ack"
        try:
            self.session.post(url, json={"status": status, "result": result}, timeout=10)
        except requests.RequestException as exc:
            # The command is already 'dispatched' server-side; a lost ack just
            # leaves it there. Acceptable at lab scale, no local retry queue.
            log.warning("ack for command %d failed (%s)", command_id, exc)
