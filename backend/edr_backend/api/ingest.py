from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..core.security import require_token
from ..schema.events import NormalizedEvent
from ..storage.models import AgentRecord
from ..storage.opensearch_client import bulk_index_events

router = APIRouter(dependencies=[Depends(require_token)])

MAX_BATCH = 1000


@router.post("/ingest")
def ingest(events: list[NormalizedEvent], db: Session = Depends(get_db)):
    if len(events) > MAX_BATCH:
        raise HTTPException(status_code=413, detail=f"batch too large (max {MAX_BATCH})")
    if not events:
        return {"accepted": 0, "errors": 0}

    docs = [e.model_dump(mode="json") for e in events]
    accepted, errors = bulk_index_events(docs)

    now = datetime.now(timezone.utc)
    for agent_id in {e.agent_id for e in events}:
        agent = db.get(AgentRecord, agent_id)
        if agent is not None:
            agent.last_seen = now
    db.commit()

    return {"accepted": accepted, "errors": len(errors)}
