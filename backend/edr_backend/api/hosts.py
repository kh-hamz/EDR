from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..core.security import require_token
from ..storage.models import AgentRecord

router = APIRouter(dependencies=[Depends(require_token)])


class EnrollRequest(BaseModel):
    hostname: str
    os: str = "linux"
    ip: str | None = None


class EnrollResponse(BaseModel):
    agent_id: str


@router.post("/hosts/enroll", response_model=EnrollResponse)
def enroll(req: EnrollRequest, db: Session = Depends(get_db)) -> EnrollResponse:
    # Re-enrollment from the same hostname returns the existing identity, so
    # reinstalling the agent does not create a duplicate host.
    existing = db.scalar(select(AgentRecord).where(AgentRecord.hostname == req.hostname))
    if existing is not None:
        existing.os = req.os
        existing.ip = req.ip
        db.commit()
        return EnrollResponse(agent_id=existing.agent_id)

    agent = AgentRecord(
        agent_id=str(uuid4()),
        hostname=req.hostname,
        os=req.os,
        ip=req.ip,
        enrolled_at=datetime.now(timezone.utc),
    )
    db.add(agent)
    db.commit()
    return EnrollResponse(agent_id=agent.agent_id)
