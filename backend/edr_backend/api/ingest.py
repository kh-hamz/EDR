from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..core.security import require_token
from edr_schema.events import NormalizedEvent
from ..storage.opensearch_client import bulk_index_events
from ..storage.repositories import AgentRepository

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

    AgentRepository(db).touch_last_seen({e.agent_id for e in events})

    return {"accepted": accepted, "errors": len(errors)}
