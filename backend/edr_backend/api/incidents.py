from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..core.security import require_token
from ..correlation.process_tree import build_process_tree
from ..correlation.timeline import build_timeline
from ..storage.opensearch_client import get_events_by_ids, search_process_events
from ..storage.repositories import IncidentRepository
from .alerts import AlertRecord

router = APIRouter(dependencies=[Depends(require_token)])

_VALID_STATUSES = {"open", "closed"}

# The process tree is rebuilt around the incident's own event window; padding
# catches the parent processes spawned shortly before the first alerting event.
_TREE_PAD_BEFORE = timedelta(minutes=15)
_TREE_PAD_AFTER = timedelta(minutes=5)


class IncidentSummary(BaseModel):
    id: int
    hostname: str
    title: str
    severity: str
    status: str
    first_alert_at: datetime
    last_alert_at: datetime
    alert_count: int


class StatusUpdate(BaseModel):
    status: str


@router.get("/incidents", response_model=list[IncidentSummary])
def list_incidents(
    status: str | None = Query(default=None), db: Session = Depends(get_db)
) -> list[IncidentSummary]:
    return [
        IncidentSummary(
            id=incident.id,
            hostname=incident.hostname,
            title=incident.title,
            severity=incident.severity,
            status=incident.status,
            first_alert_at=incident.first_alert_at,
            last_alert_at=incident.last_alert_at,
            alert_count=count,
        )
        for incident, count in IncidentRepository(db).list_all(status=status)
    ]


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db)) -> dict:
    """Full incident view: member alerts, event timeline, and the process
    tree on that host around the incident window."""
    repo = IncidentRepository(db)
    incident = repo.get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")

    alerts = repo.alerts_for(incident_id)
    events = get_events_by_ids([a.event_id for a in alerts])
    timeline = build_timeline(events, alerts)

    # Window the tree on the *event* times (detection lags the events by up
    # to the loop tick + lookback, so alert times would start too late).
    if events:
        event_times = [datetime.fromisoformat(e["time"]) for e in events]
        window_start, window_end = min(event_times), max(event_times)
    else:
        window_start, window_end = incident.first_alert_at, incident.last_alert_at
    process_events = search_process_events(
        hostname=incident.hostname,
        since=(window_start - _TREE_PAD_BEFORE).isoformat(),
        until=(window_end + _TREE_PAD_AFTER).isoformat(),
    )

    return {
        "id": incident.id,
        "hostname": incident.hostname,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "first_alert_at": incident.first_alert_at,
        "last_alert_at": incident.last_alert_at,
        "alerts": [AlertRecord.model_validate(a) for a in alerts],
        "timeline": timeline,
        "process_tree": build_process_tree(process_events),
    }


@router.patch("/incidents/{incident_id}", response_model=IncidentSummary)
def update_incident_status(
    incident_id: int, req: StatusUpdate, db: Session = Depends(get_db)
) -> IncidentSummary:
    if req.status not in _VALID_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {_VALID_STATUSES}")
    repo = IncidentRepository(db)
    incident = repo.update_status(incident_id, req.status)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    alert_count = len(repo.alerts_for(incident_id))
    return IncidentSummary(
        id=incident.id,
        hostname=incident.hostname,
        title=incident.title,
        severity=incident.severity,
        status=incident.status,
        first_alert_at=incident.first_alert_at,
        last_alert_at=incident.last_alert_at,
        alert_count=alert_count,
    )
