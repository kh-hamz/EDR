from edr_backend.storage.opensearch_client import build_events_query


def test_no_filters_matches_all():
    assert build_events_query() == {"match_all": {}}


def test_single_filter():
    query = build_events_query(hostname="victim-01")
    assert query == {"bool": {"filter": [{"term": {"host.hostname": "victim-01"}}]}}


def test_combines_multiple_filters():
    query = build_events_query(hostname="victim-01", event_type="process_create", process_name="nc")
    assert query["bool"]["filter"] == [
        {"term": {"host.hostname": "victim-01"}},
        {"term": {"event_type": "process_create"}},
        {"term": {"process.name": "nc"}},
    ]


def test_time_range_uses_gte_lte():
    query = build_events_query(since="2026-07-06T00:00:00Z", until="2026-07-07T00:00:00Z")
    assert query["bool"]["filter"] == [
        {"range": {"time": {"gte": "2026-07-06T00:00:00Z", "lte": "2026-07-07T00:00:00Z"}}}
    ]


def test_since_only_omits_lte():
    query = build_events_query(since="2026-07-06T00:00:00Z")
    assert query["bool"]["filter"] == [{"range": {"time": {"gte": "2026-07-06T00:00:00Z"}}}]
