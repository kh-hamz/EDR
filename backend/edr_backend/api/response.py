from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..core.security import require_token
from ..response.issuer import IssueError, issue_command
from ..storage.repositories import CommandRepository

router = APIRouter(dependencies=[Depends(require_token)])


class IssueRequest(BaseModel):
    hostname: str
    action: str
    params: dict = {}


class CommandRecord(BaseModel):
    id: int
    agent_id: str
    hostname: str
    action: str
    params: dict
    status: str
    result: str | None
    source_alert_id: int | None
    created_at: datetime
    dispatched_at: datetime | None
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class AckRequest(BaseModel):
    status: str  # "succeeded" | "failed"
    result: str | None = None


@router.post("/response", response_model=CommandRecord, status_code=201)
def issue(req: IssueRequest, db: Session = Depends(get_db)) -> CommandRecord:
    """Manually issue a response command (e.g. the console 'isolate' button)."""
    try:
        command = issue_command(db, req.hostname, req.action, req.params)
    except IssueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return CommandRecord.model_validate(command)


@router.get("/response/commands", response_model=list[CommandRecord])
def poll_or_list(
    agent_id: str | None = Query(default=None),
    hostname: str | None = Query(default=None),
    status: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[CommandRecord]:
    """Two callers, one endpoint:
    - agent poll (agent_id set): claim this agent's pending commands, moving
      them to 'dispatched' so a retry doesn't re-run them.
    - console list (no agent_id): read-only listing, optionally filtered."""
    repo = CommandRepository(db)
    if agent_id is not None:
        commands = repo.claim_pending(agent_id)
    else:
        commands = repo.list_all(hostname=hostname, status=status)
    return [CommandRecord.model_validate(c) for c in commands]


@router.post("/response/commands/{command_id}/ack", response_model=CommandRecord)
def ack(command_id: int, req: AckRequest, db: Session = Depends(get_db)) -> CommandRecord:
    """Agent reports the outcome of a dispatched command."""
    if req.status not in ("succeeded", "failed"):
        raise HTTPException(status_code=422, detail="status must be 'succeeded' or 'failed'")
    command = CommandRepository(db).complete(command_id, req.status, req.result)
    if command is None:
        raise HTTPException(status_code=404, detail="command not found")
    return CommandRecord.model_validate(command)
