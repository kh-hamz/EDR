from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..ai import nl2query
from ..ai.llm_client import LLMNotConfigured
from ..core.security import require_token
from ..storage.opensearch_client import search_events

router = APIRouter(dependencies=[Depends(require_token)])


class HuntRequest(BaseModel):
    query: str
    size: int = 50


@router.post("/hunt")
def hunt(req: HuntRequest) -> dict:
    """NL query -> translated filters -> executed search, in one call. The
    translation alone (filters + compiled query, no execution) is available
    at POST /ai/nl2query for callers that want to inspect or edit it first."""
    try:
        translated = nl2query.translate(req.query)
    except LLMNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    filters = translated["filters"]
    total, events = search_events(
        hostname=filters["hostname"],
        event_type=filters["event_type"],
        process_name=filters["process_name"],
        since=translated["since"],
        size=req.size,
    )
    return {"filters": filters, "total": total, "events": events}
