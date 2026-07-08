"""Assembles an incident timeline: the events behind the incident's alerts,
in time order, each annotated with the rule(s) that fired on it. Pure
function so it unit-tests without OpenSearch or Postgres.
"""


def _summarize(event: dict) -> str:
    body_type = event["event_type"]
    if body_type in ("process_create", "process_terminate"):
        proc = event.get("process") or {}
        return proc.get("cmdline") or proc.get("name") or f"pid {proc.get('pid')}"
    if body_type == "file_event":
        f = event.get("file") or {}
        return f"{f.get('action')} {f.get('path')}"
    if body_type == "network_connection":
        n = event.get("network") or {}
        return f"{n.get('process_name') or '?'} -> {n.get('dst_ip')}:{n.get('dst_port')}"
    if body_type == "auth_event":
        a = event.get("auth") or {}
        return f"{a.get('action')} user={a.get('user')} result={a.get('result')}"
    if body_type == "inventory":
        inv = event.get("inventory") or {}
        return f"{inv.get('query_name')} ({inv.get('action')})"
    return body_type


def build_timeline(events: list[dict], alerts: list) -> list[dict]:
    """alerts: Alert ORM rows (or anything with event_id/rule_id/title/severity)."""
    rules_by_event: dict[str, list[dict]] = {}
    for alert in alerts:
        rules_by_event.setdefault(alert.event_id, []).append(
            {"rule_id": alert.rule_id, "title": alert.title, "severity": alert.severity}
        )

    return [
        {
            "time": event["time"],
            "event_id": event["event_id"],
            "event_type": event["event_type"],
            "summary": _summarize(event),
            "alerts": rules_by_event.get(event["event_id"], []),
        }
        for event in sorted(events, key=lambda e: e["time"])
    ]
