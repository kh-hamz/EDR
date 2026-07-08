"""Auto-response playbooks: a detection fires -> a command is issued with no
human in the loop. Scope is deliberately one high-confidence rule (netcat
reverse shell) mapped to kill_process, since auto-actions on false positives
are costly. Everything else stays manual through the API.

Idempotency comes from two layers: only alerts without a command yet are
considered, and Command's unique source_alert_id makes a double-issue a no-op
even if two runs race.
"""

import logging

from sqlalchemy.orm import Session

from ..core.db import SessionLocal
from ..storage.opensearch_client import get_events_by_ids
from ..storage.repositories import AlertRepository
from .issuer import IssueError, issue_command

log = logging.getLogger(__name__)

# The netcat reverse-shell Sigma rule (level: critical). Its matching event is
# a process_create, so process.pid is the shell to kill.
_REVERSE_SHELL_RULE_ID = "8f1b9a2e-1a1b-4c1a-9f1a-000000000002"


def run_playbooks(db: Session) -> int:
    """Issue auto-commands for eligible alerts. Returns how many were issued."""
    alerts = AlertRepository(db).list_by_rule_without_command(_REVERSE_SHELL_RULE_ID)
    if not alerts:
        return 0

    events = {e["event_id"]: e for e in get_events_by_ids([a.event_id for a in alerts])}

    issued = 0
    for alert in alerts:
        event = events.get(alert.event_id)
        pid = ((event or {}).get("process") or {}).get("pid")
        if pid is None:
            log.warning(
                "reverse-shell alert %d has no process pid, skipping auto-kill", alert.id
            )
            continue
        try:
            command = issue_command(
                db,
                hostname=alert.hostname,
                action="kill_process",
                params={"pid": pid},
                source_alert_id=alert.id,
            )
        except IssueError as exc:
            log.warning("auto-kill for alert %d not issued: %s", alert.id, exc)
            continue
        issued += 1
        log.info(
            "auto-playbook: kill_process pid=%d on %s (alert %d, command %d)",
            pid, alert.hostname, alert.id, command.id,
        )

    return issued


def run_playbooks_standalone() -> int:
    """Session-owning wrapper for the background loop, mirroring run_detection."""
    db = SessionLocal()
    try:
        return run_playbooks(db)
    finally:
        db.close()
