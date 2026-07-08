"""The actual response actions the agent runs on the endpoint.

Each action returns a short human-readable result string on success and
raises ActionFailed on failure; the poller turns that into the ack status.
These need root (iptables, killing other users' processes, moving files) -
the agent runs as root on the victim, which is why the whole responder is a
lab-only capability.

Host isolation uses two dedicated iptables chains (EDR_ISO_IN / EDR_ISO_OUT)
jumped from INPUT/OUTPUT, so unisolation is a clean teardown that never
touches pre-existing firewall rules. The backend address stays allowed so the
agent can still receive the unisolate command.
"""

import os
import shutil
import signal
import subprocess
from datetime import datetime, timezone
from pathlib import Path

_ISO_IN = "EDR_ISO_IN"
_ISO_OUT = "EDR_ISO_OUT"


class ActionFailed(Exception):
    pass


def _run(cmd: list[str], check: bool = True) -> None:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise ActionFailed(f"{' '.join(cmd)} failed: {result.stderr.strip()}")


def kill_process(pid: int) -> str:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return f"pid {pid} already gone"
    except PermissionError as exc:
        raise ActionFailed(f"not permitted to kill pid {pid}: {exc}") from exc
    return f"killed pid {pid}"


def isolate_host(allow_host: str) -> str:
    """Drop all traffic except loopback, established flows, and the backend."""
    _teardown_isolation()  # start from a known state so re-isolating is safe
    for chain in (_ISO_IN, _ISO_OUT):
        _run(["iptables", "-N", chain])
    _run(["iptables", "-A", _ISO_IN, "-i", "lo", "-j", "ACCEPT"])
    _run(["iptables", "-A", _ISO_IN, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    _run(["iptables", "-A", _ISO_IN, "-s", allow_host, "-j", "ACCEPT"])
    _run(["iptables", "-A", _ISO_IN, "-j", "DROP"])
    _run(["iptables", "-A", _ISO_OUT, "-o", "lo", "-j", "ACCEPT"])
    _run(["iptables", "-A", _ISO_OUT, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    _run(["iptables", "-A", _ISO_OUT, "-d", allow_host, "-j", "ACCEPT"])
    _run(["iptables", "-A", _ISO_OUT, "-j", "DROP"])
    _run(["iptables", "-I", "INPUT", "1", "-j", _ISO_IN])
    _run(["iptables", "-I", "OUTPUT", "1", "-j", _ISO_OUT])
    return f"host isolated (backend {allow_host} still reachable)"


def unisolate_host() -> str:
    _teardown_isolation()
    return "host isolation lifted"


def _teardown_isolation() -> None:
    # Order matters: remove the jumps before flushing/deleting the chains.
    # check=False throughout so a partial or absent setup still tears down.
    _run(["iptables", "-D", "INPUT", "-j", _ISO_IN], check=False)
    _run(["iptables", "-D", "OUTPUT", "-j", _ISO_OUT], check=False)
    for chain in (_ISO_IN, _ISO_OUT):
        _run(["iptables", "-F", chain], check=False)
        _run(["iptables", "-X", chain], check=False)


def quarantine_file(path: str, quarantine_dir: str) -> str:
    """Move the file into the quarantine dir (root-only, perms 000) so it can
    neither execute nor be read, while staying available for later analysis."""
    src = Path(path)
    if not src.exists():
        raise ActionFailed(f"file not found: {path}")

    dest_dir = Path(quarantine_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(dest_dir, 0o700)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = dest_dir / f"{stamp}_{src.name}"
    shutil.move(str(src), str(dest))
    os.chmod(dest, 0o000)
    return f"quarantined {path} -> {dest}"
