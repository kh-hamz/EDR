from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..core.security import require_token
from ..correlation.incident_view import build_incident_view
from ..storage.repositories import IncidentRepository
from .alerts import AlertRecord

router = APIRouter(dependencies=[Depends(require_token)])

_VALID_STATUSES = {"open", "closed"}


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
    view = build_incident_view(db, incident_id)
    if view is None:
        raise HTTPException(status_code=404, detail="incident not found")

    incident = view["incident"]
    return {
        "id": incident.id,
        "hostname": incident.hostname,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "first_alert_at": incident.first_alert_at,
        "last_alert_at": incident.last_alert_at,
        "alerts": [AlertRecord.model_validate(a) for a in view["alerts"]],
        "timeline": view["timeline"],
        "process_tree": view["process_tree"],
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
