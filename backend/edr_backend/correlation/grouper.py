"""Groups alerts into incidents.

Policy: an unassigned alert joins the most recent open incident on the same
host whose last alert was within INCIDENT_GAP; otherwise it starts a new
incident. Incident severity escalates to the max of its member alerts.
Processing unassigned alerts oldest-first makes the pass deterministic and
idempotent - already-assigned alerts are never touched, so re-running after
a missed tick is a no-op.
"""

import logging
from datetime import timedelta

from sqlalchemy.orm import Session

from ..core.db import SessionLocal
from ..storage.repositories import AlertRepository, IncidentRepository

log = logging.getLogger(__name__)

INCIDENT_GAP = timedelta(minutes=30)

_SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _escalate(current: str, incoming: str) -> str:
    return max(current, incoming, key=lambda s: _SEVERITY_RANK.get(s, 0))


def correlate_alerts(db: Session) -> int:
    """Assigns every unassigned alert to an incident. Returns how many
    alerts were assigned."""
    alert_repo = AlertRepository(db)
    incident_repo = IncidentRepository(db)

    assigned = 0
    for alert in alert_repo.list_unassigned():
        incident = incident_repo.find_open_since(
            alert.hostname, alert.created_at - INCIDENT_GAP
        )
        if incident is None:
            incident = incident_repo.create(
                hostname=alert.hostname,
                title=alert.title,
                severity=alert.severity,
                alert_time=alert.created_at,
            )
            log.info("incident %d opened on %s: %s", incident.id, alert.hostname, alert.title)
        incident_repo.attach_alert(
            incident, alert, severity=_escalate(incident.severity, alert.severity)
        )
        assigned += 1

    return assigned


def run_correlation() -> int:
    """Session-owning wrapper for callers outside a request context (the
    background loop), mirroring detection.engine.run_detection."""
    db = SessionLocal()
    try:
        return correlate_alerts(db)
    finally:
        db.close()
