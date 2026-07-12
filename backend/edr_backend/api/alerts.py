from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..core.security import require_token
from ..storage.repositories import AlertRepository

router = APIRouter(dependencies=[Depends(require_token)])

_VALID_STATUSES = {"open", "acknowledged", "dismissed", "closed"}


class AlertRecord(BaseModel):
    id: int
    event_id: str
    rule_id: str
    title: str
    severity: str
    tactic: str | None
    technique_id: str | None
    hostname: str
    created_at: datetime
    status: str
    incident_id: int | None = None

    model_config = {"from_attributes": True}


class StatusUpdate(BaseModel):
    status: str


@router.get("/alerts", response_model=list[AlertRecord])
def list_alerts(
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[AlertRecord]:
    return [
        AlertRecord.model_validate(a)
        for a in AlertRepository(db).list_all(status=status, severity=severity)
    ]


@router.patch("/alerts/{alert_id}", response_model=AlertRecord)
def update_alert_status(
    alert_id: int, req: StatusUpdate, db: Session = Depends(get_db)
) -> AlertRecord:
    if req.status not in _VALID_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {_VALID_STATUSES}")
    alert = AlertRepository(db).update_status(alert_id, req.status)
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return AlertRecord.model_validate(alert)
