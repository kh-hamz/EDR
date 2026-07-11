"""Incident -> plain-English narrative + recommended response.

Prompt-building is pure (testable without a live LLM); only summarize()
calls out. Renders the same incident view the console shows (timeline +
process tree), so the narrative is grounded in exactly what an analyst sees.
"""

from . import llm_client

_SYSTEM = """You are a SOC analyst assistant. You are given one security \
incident from an EDR system: its member alerts, an event timeline, and a \
process tree. Write a concise incident summary for a human analyst.

Structure your response as:
1. One-paragraph narrative of what happened, in plain English, in \
chronological order.
2. Severity assessment (does the system's tagged severity look right given \
the evidence).
3. Recommended response (concrete next action: e.g. isolate the host, kill \
a specific process, rotate credentials, or note if it looks like a false \
positive).

Be concise. Do not restate the raw timeline verbatim - synthesize it."""


def _format_alerts(alerts) -> str:
    return "\n".join(
        f"- [{a.severity}] {a.title} (rule {a.rule_id}, technique {a.technique_id})"
        for a in alerts
    )


def _format_timeline(timeline: list[dict]) -> str:
    lines = []
    for entry in timeline:
        rules = ", ".join(a["title"] for a in entry["alerts"])
        tag = f" <- {rules}" if rules else ""
        lines.append(f"{entry['time']} [{entry['event_type']}] {entry['summary']}{tag}")
    return "\n".join(lines)


def _format_tree(tree: list[dict], depth: int = 0) -> str:
    lines = []
    for node in tree:
        marker = " (unobserved parent)" if node["event_id"] is None else ""
        lines.append(
            "  " * depth
            + f"{node['pid']} {node['name'] or '?'}: {node['cmdline'] or ''}{marker}"
        )
        lines.extend(_format_tree(node["children"], depth + 1).splitlines())
    return "\n".join(lines)


def build_prompt(incident, alerts: list, timeline: list[dict], process_tree: list[dict]) -> str:
    return f"""Incident: {incident.title}
Host: {incident.hostname}
Severity: {incident.severity}
Window: {incident.first_alert_at} to {incident.last_alert_at}

Alerts ({len(alerts)}):
{_format_alerts(alerts)}

Timeline:
{_format_timeline(timeline)}

Process tree:
{_format_tree(process_tree)}"""


def summarize_incident(incident, alerts: list, timeline: list[dict], process_tree: list[dict]) -> str:
    prompt = build_prompt(incident, alerts, timeline, process_tree)
    return llm_client.complete(_SYSTEM, prompt)
