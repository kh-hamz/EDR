"""Map raw sensor payloads to the shared NormalizedEvent schema.

Mappings live in code (not per-source YAML) while there are only two sources;
the indirection of a mapping DSL is not worth it yet.

Falco event classification: our telemetry rules in deploy/falco/edr_rules.yaml
are matched by rule name. Any other Falco rule (the stock security ruleset)
is classified by which output_fields it carries, falling back to
process_create when process context is all we have.
"""

import logging
import re
from datetime import datetime, timezone

from edr_schema.events import (
    FileInfo,
    HostInfo,
    InventoryInfo,
    NetworkInfo,
    NormalizedEvent,
    ParentProcessInfo,
    ProcessInfo,
    UserInfo,
)

log = logging.getLogger(__name__)

RULE_PROCESS_SPAWN = "EDR process spawned"
RULE_OUTBOUND_CONN = "EDR outbound connection"

_FILE_ACTIONS = {
    "open": "read",
    "openat": "read",
    "openat2": "read",
    "read": "read",
    "write": "modify",
    "creat": "create",
    "mkdir": "create",
    "mkdirat": "create",
    "unlink": "delete",
    "unlinkat": "delete",
    "rmdir": "delete",
    "rename": "rename",
    "renameat": "rename",
    "renameat2": "rename",
}


def normalize(raw: dict, observer: str, agent_id: str, host: HostInfo) -> list[NormalizedEvent]:
    try:
        if observer == "falco":
            return _from_falco(raw, agent_id, host)
        if observer == "osquery":
            return _from_osquery(raw, agent_id, host)
    except Exception:
        log.exception("failed to normalize %s event: %.200s", observer, raw)
        return []
    return []


# --- falco ---

def _from_falco(raw: dict, agent_id: str, host: HostInfo) -> list[NormalizedEvent]:
    of = raw.get("output_fields") or {}
    rule = raw.get("rule", "")
    time = _parse_falco_time(raw.get("time"))
    common = {"agent_id": agent_id, "host": host, "observer": "falco", "time": time, "raw": raw}

    if rule == RULE_OUTBOUND_CONN or ("fd.dip" in of and of.get("fd.dip")):
        return [NormalizedEvent(
            event_type="network_connection",
            network=NetworkInfo(
                direction="outbound",
                proto=of.get("fd.l4proto"),
                src_ip=of.get("fd.sip") or of.get("fd.cip"),
                src_port=_to_int(of.get("fd.sport") or of.get("fd.cport")),
                dst_ip=of.get("fd.dip") or of.get("fd.sip"),
                dst_port=_to_int(of.get("fd.dport")),
                pid=_to_int(of.get("proc.pid")),
                process_name=of.get("proc.name"),
            ),
            process=_falco_process(of),
            **common,
        )]

    evt_type = of.get("evt.type", "")
    fd_name = of.get("fd.name")
    if evt_type in _FILE_ACTIONS and fd_name and rule != RULE_PROCESS_SPAWN:
        return [NormalizedEvent(
            event_type="file_event",
            file=FileInfo(path=fd_name, action=_FILE_ACTIONS[evt_type]),
            process=_falco_process(of),
            **common,
        )]

    proc = _falco_process(of)
    if proc is not None:
        return [NormalizedEvent(event_type="process_create", process=proc, **common)]

    log.debug("falco event with no mappable fields, rule=%s", rule)
    return []


def _falco_process(of: dict) -> ProcessInfo | None:
    pid = _to_int(of.get("proc.pid"))
    if pid is None:
        return None
    parent = None
    if of.get("proc.pname") or of.get("proc.ppid"):
        parent = ParentProcessInfo(
            pid=_to_int(of.get("proc.ppid")),
            name=of.get("proc.pname"),
            cmdline=of.get("proc.pcmdline"),
        )
    user = None
    if of.get("user.name") or of.get("user.uid") is not None:
        user = UserInfo(name=of.get("user.name"), uid=_to_int(of.get("user.uid")))
    return ProcessInfo(
        pid=pid,
        ppid=_to_int(of.get("proc.ppid")),
        name=of.get("proc.name"),
        cmdline=of.get("proc.cmdline"),
        exe=of.get("proc.exepath"),
        user=user,
        parent=parent,
    )


def _parse_falco_time(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    # Falco emits nanosecond precision ("...T12:00:00.123456789Z");
    # datetime.fromisoformat only accepts up to microseconds, so trim.
    trimmed = re.sub(r"(\.\d{6})\d+", r"\1", value)
    try:
        return datetime.fromisoformat(trimmed.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


# --- osquery ---

def _from_osquery(raw: dict, agent_id: str, host: HostInfo) -> list[NormalizedEvent]:
    name = raw.get("name")
    if not name:
        return []
    unix = _to_int(raw.get("unixTime"))
    time = datetime.fromtimestamp(unix, tz=timezone.utc) if unix else datetime.now(timezone.utc)

    if "snapshot" in raw:
        rows = raw["snapshot"]
        action = "snapshot"
        # keep raw light: the rows themselves land in each event's inventory body
        raw_meta = {k: v for k, v in raw.items() if k != "snapshot"}
    else:
        rows = [raw.get("columns", {})]
        action = raw.get("action", "added")
        raw_meta = raw

    return [
        NormalizedEvent(
            event_type="inventory",
            inventory=InventoryInfo(query_name=name, action=action, columns=row),
            agent_id=agent_id,
            host=host,
            observer="osquery",
            time=time,
            raw=raw_meta,
        )
        for row in rows
    ]


def _to_int(value) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
