from fastapi import APIRouter, Depends, Query

from ..core.security import require_token
from ..storage.opensearch_client import search_events

router = APIRouter(dependencies=[Depends(require_token)])

MAX_SIZE = 500


@router.get("/events")
def list_events(
    host: str | None = Query(default=None, description="Filter by host.hostname"),
    event_type: str | None = Query(default=None),
    process_name: str | None = Query(default=None, description="Filter by process.name"),
    since: str | None = Query(default=None, description="ISO-8601, inclusive lower bound on time"),
    until: str | None = Query(default=None, description="ISO-8601, inclusive upper bound on time"),
    size: int = Query(default=50, le=MAX_SIZE, gt=0),
    from_: int = Query(default=0, ge=0, alias="from"),
):
    total, events = search_events(
        hostname=host,
        event_type=event_type,
        process_name=process_name,
        since=since,
        until=until,
        size=size,
        from_=from_,
    )
    return {"total": total, "events": events}
