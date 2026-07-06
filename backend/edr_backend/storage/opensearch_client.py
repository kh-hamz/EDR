from opensearchpy import OpenSearch, helpers

from ..core.config import settings

client = OpenSearch(settings.opensearch_url)


def index_for(time_iso: str) -> str:
    """Daily indices: edr-events-2026.07.05. time_iso is ISO-8601 (schema output)."""
    return f"{settings.edr_index_prefix}-{time_iso[:10].replace('-', '.')}"


def bulk_index_events(events: list[dict]) -> tuple[int, list]:
    """Bulk-write normalized event dicts. event_id doubles as the doc _id,
    which makes agent retries after a lost ack idempotent instead of
    duplicating events."""
    actions = (
        {
            "_index": index_for(e["time"]),
            "_id": e["event_id"],
            "_source": e,
        }
        for e in events
    )
    success, errors = helpers.bulk(client, actions, raise_on_error=False)
    return success, errors
