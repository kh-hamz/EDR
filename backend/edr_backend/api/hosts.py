from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..core.security import require_token
from ..storage.repositories import AgentRepository

router = APIRouter(dependencies=[Depends(require_token)])


class EnrollRequest(BaseModel):
    hostname: str
    os: str = "linux"
    ip: str | None = None


class EnrollResponse(BaseModel):
    agent_id: str


class HostRecord(BaseModel):
    agent_id: str
    hostname: str
    os: str
    ip: str | None
    enrolled_at: datetime
    last_seen: datetime | None

    model_config = {"from_attributes": True}


@router.post("/hosts/enroll", response_model=EnrollResponse)
def enroll(req: EnrollRequest, db: Session = Depends(get_db)) -> EnrollResponse:
    # Re-enrollment from the same hostname returns the existing identity, so
    # reinstalling the agent does not create a duplicate host.
    agent = AgentRepository(db).upsert(
        agent_id=str(uuid4()), hostname=req.hostname, os=req.os, ip=req.ip
    )
    return EnrollResponse(agent_id=agent.agent_id)


@router.get("/hosts", response_model=list[HostRecord])
def list_hosts(db: Session = Depends(get_db)) -> list[HostRecord]:
    return [HostRecord.model_validate(a) for a in AgentRepository(db).list_all()]
