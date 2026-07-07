from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query

from ..core.security import require_token
from ..detection.engine import run_detection

router = APIRouter(dependencies=[Depends(require_token)])


@router.post("/detection/run")
def trigger_detection(
    lookback_minutes: int = Query(
        default=60, gt=0, le=1440, description="How far back to re-scan"
    ),
):
    """Manual trigger, independent of the background loop's tick - useful right
    after running an Atomic Red Team test instead of waiting for the next tick."""
    since = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
    created = run_detection(since)
    return {"alerts_created": created}
