"""Natural language -> OpenSearch query, e.g. "show me all outbound
connections from www-data in the last 24h" -> a filtered events search.

Splits the work in two: the LLM extracts *structured filters* (hostname,
event_type, process_name, a relative lookback) via structured outputs; this
module resolves the lookback to an absolute `since` timestamp and hands the
filters to storage.build_events_query, so the actual query DSL stays owned
by the storage layer (same rule as detection/correlation).
"""

from datetime import datetime, timedelta, timezone
from typing import get_args

from edr_schema.events import EventType

from ..storage.opensearch_client import build_events_query
from . import llm_client

_EVENT_TYPES = list(get_args(EventType))

_SYSTEM = """Extract search filters from a security analyst's natural- \
language query about EDR events. Only fill fields the query actually \
specifies; leave the rest null. lookback_minutes is how far back to search \
(e.g. "last 24h" -> 1440, "last hour" -> 60); null means no time bound."""

_SCHEMA = {
    "type": "object",
    "properties": {
        "hostname": {"type": ["string", "null"]},
        "event_type": {"type": ["string", "null"], "enum": [*_EVENT_TYPES, None]},
        "process_name": {"type": ["string", "null"]},
        "lookback_minutes": {"type": ["integer", "null"]},
    },
    "required": ["hostname", "event_type", "process_name", "lookback_minutes"],
    "additionalProperties": False,
}


def extract_filters(nl_query: str) -> dict:
    """Pure LLM call: NL -> the structured filter fields above."""
    return llm_client.complete_structured(_SYSTEM, nl_query, _SCHEMA)


def translate(nl_query: str) -> dict:
    """NL -> a ready-to-run OpenSearch query dict, plus the filters that
    produced it (so the caller/UI can show what was understood)."""
    filters = extract_filters(nl_query)

    since = None
    if filters["lookback_minutes"] is not None:
        since = (
            datetime.now(timezone.utc) - timedelta(minutes=filters["lookback_minutes"])
        ).isoformat()

    query = build_events_query(
        hostname=filters["hostname"],
        event_type=filters["event_type"],
        process_name=filters["process_name"],
        since=since,
    )
    return {"filters": filters, "since": since, "query": query}
