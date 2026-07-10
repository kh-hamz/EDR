"""Assembles the full view of one incident: member alerts, event timeline,
and the process tree on that host around the incident window. Shared by
api/incidents.py (the console view) and ai/summarizer.py (the LLM prompt),
so both see the exact same data.
"""

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from ..storage.models import Incident
from ..storage.opensearch_client import get_events_by_ids, search_process_events
from ..storage.repositories import IncidentRepository
from .process_tree import build_process_tree
from .timeline import build_timeline

# The process tree is rebuilt around the incident's own event window; padding
# catches the parent processes spawned shortly before the first alerting event.
_TREE_PAD_BEFORE = timedelta(minutes=15)
_TREE_PAD_AFTER = timedelta(minutes=5)


def build_incident_view(db: Session, incident_id: int) -> dict | None:
    """Returns None if the incident doesn't exist. Otherwise a dict with
    the Incident ORM row (`incident`), its alerts, timeline, and process
    tree - the same shape api/incidents.py exposes over the wire."""
    repo = IncidentRepository(db)
    incident: Incident | None = repo.get(incident_id)
    if incident is None:
        return None

    alerts = repo.alerts_for(incident_id)
    events = get_events_by_ids([a.event_id for a in alerts])
    timeline = build_timeline(events, alerts)

    # Window the tree on the *event* times (detection lags the events by up
    # to the loop tick + lookback, so alert times would start too late).
    if events:
        event_times = [datetime.fromisoformat(e["time"]) for e in events]
        window_start, window_end = min(event_times), max(event_times)
    else:
        window_start, window_end = incident.first_alert_at, incident.last_alert_at
    process_events = search_process_events(
        hostname=incident.hostname,
        since=(window_start - _TREE_PAD_BEFORE).isoformat(),
        until=(window_end + _TREE_PAD_AFTER).isoformat(),
    )

    return {
        "incident": incident,
        "alerts": alerts,
        "timeline": timeline,
        "process_tree": build_process_tree(process_events),
    }
