"""First-run enrollment: register with the backend, persist the agent_id."""

import json
import logging
import socket
import threading
from pathlib import Path

import requests

from edr_schema.events import HostInfo

from .config import AgentSettings

log = logging.getLogger(__name__)


def ensure_enrolled(settings: AgentSettings, stop: threading.Event) -> tuple[str, HostInfo] | None:
    """Returns (agent_id, host) or None if stopped while waiting for the backend."""
    hostname = settings.hostname or socket.gethostname()
    ip = settings.ip or _primary_ip()

    state_path = Path(settings.state_path)
    if state_path.exists():
        agent_id = json.loads(state_path.read_text())["agent_id"]
        return agent_id, _host(agent_id, hostname, ip)

    url = f"{settings.backend_url}/hosts/enroll"
    headers = {"Authorization": f"Bearer {settings.api_token}"}
    payload = {"hostname": hostname, "os": "linux", "ip": ip}

    backoff = 2.0
    while not stop.is_set():
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=10)
            resp.raise_for_status()
            agent_id = resp.json()["agent_id"]
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(json.dumps({"agent_id": agent_id}))
            log.info("enrolled as %s (%s)", agent_id, hostname)
            return agent_id, _host(agent_id, hostname, ip)
        except requests.RequestException as exc:
            log.warning("enrollment failed (%s), retrying in %.0fs", exc, backoff)
            stop.wait(backoff)
            backoff = min(backoff * 2, 60.0)
    return None


def _host(agent_id: str, hostname: str, ip: str | None) -> HostInfo:
    # host_id == agent_id until multi-agent-per-host becomes a thing (it won't here)
    return HostInfo(host_id=agent_id, hostname=hostname, os="linux", ip=ip)


def _primary_ip() -> str | None:
    """The IP of the default route interface; no packet is actually sent."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return None
