import json
from pathlib import Path

from opensearchpy import OpenSearch, helpers

from ..core.config import settings

client = OpenSearch(settings.opensearch_url)

_INDEX_TEMPLATE_NAME = "edr-events"
_INDEX_TEMPLATE_PATH = (
    Path(__file__).resolve().parents[3] / "deploy" / "opensearch" / "event-index-template.json"
)


def ensure_index_template() -> None:
    """Idempotently PUT the event mapping so new daily indices (edr-events-YYYY.MM.DD)
    get consistent field types instead of relying on dynamic mapping guesses."""
    template = json.loads(_INDEX_TEMPLATE_PATH.read_text())
    client.indices.put_index_template(name=_INDEX_TEMPLATE_NAME, body=template)


def index_for(time_iso: str) -> str:
    """Daily indices: edr-events-2026.07.05. time_iso is ISO-8601 (schema output)."""
    return f"{settings.edr_index_prefix}-{time_iso[:10].replace('-', '.')}"


def _events_index_pattern() -> str:
    """The wildcard spanning every daily index, for cross-day searches."""
    return f"{settings.edr_index_prefix}-*"


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


def build_events_query(
    hostname: str | None = None,
    event_type: str | None = None,
    process_name: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> dict:
    """Pure query-DSL builder, kept separate from execution so it's unit-testable
    without a live OpenSearch instance."""
    filters: list[dict] = []
    if hostname:
        filters.append({"term": {"host.hostname": hostname}})
    if event_type:
        filters.append({"term": {"event_type": event_type}})
    if process_name:
        filters.append({"term": {"process.name": process_name}})
    if since or until:
        rng: dict = {}
        if since:
            rng["gte"] = since
        if until:
            rng["lte"] = until
        filters.append({"range": {"time": rng}})

    return {"bool": {"filter": filters}} if filters else {"match_all": {}}


def search_events(
    hostname: str | None = None,
    event_type: str | None = None,
    process_name: str | None = None,
    since: str | None = None,
    until: str | None = None,
    size: int = 50,
    from_: int = 0,
) -> tuple[int, list[dict]]:
    query = build_events_query(hostname, event_type, process_name, since, until)
    resp = client.search(
        index=_events_index_pattern(),
        body={"query": query, "sort": [{"time": "desc"}], "size": size, "from": from_},
    )
    total = resp["hits"]["total"]["value"]
    docs = [hit["_source"] for hit in resp["hits"]["hits"]]
    return total, docs


def search_rule_matches(lucene_query: str, since: str, size: int = 200) -> list[dict]:
    """Run a compiled Sigma rule (a Lucene query string) against events at or
    after `since` (ISO-8601), returning the matching `_source` dicts. Keeps
    OpenSearch DSL and the raw client in the storage layer, so the detection
    engine only expresses intent ('events this rule matched since T')."""
    query = {
        "bool": {
            "must": [{"query_string": {"query": lucene_query}}],
            "filter": [{"range": {"time": {"gte": since}}}],
        }
    }
    resp = client.search(
        index=_events_index_pattern(),
        body={"query": query, "size": size},
    )
    return [hit["_source"] for hit in resp["hits"]["hits"]]
