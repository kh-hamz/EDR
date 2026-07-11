from edr_backend.ai import nl2query


def test_translate_resolves_lookback_to_since(monkeypatch):
    monkeypatch.setattr(
        nl2query.llm_client, "complete_structured",
        lambda system, user, schema: {
            "hostname": None, "event_type": "network_connection",
            "process_name": "www-data", "lookback_minutes": 1440,
        },
    )
    result = nl2query.translate("outbound connections from www-data in the last 24h")
    assert result["filters"]["process_name"] == "www-data"
    assert result["since"] is not None
    assert result["query"]["bool"]["filter"]


def test_translate_with_no_time_bound(monkeypatch):
    monkeypatch.setattr(
        nl2query.llm_client, "complete_structured",
        lambda system, user, schema: {
            "hostname": "victim-01", "event_type": None,
            "process_name": None, "lookback_minutes": None,
        },
    )
    result = nl2query.translate("everything on victim-01")
    assert result["since"] is None
    assert result["filters"]["hostname"] == "victim-01"


def test_translate_with_no_filters_returns_match_all(monkeypatch):
    monkeypatch.setattr(
        nl2query.llm_client, "complete_structured",
        lambda system, user, schema: {
            "hostname": None, "event_type": None,
            "process_name": None, "lookback_minutes": None,
        },
    )
    result = nl2query.translate("show me everything")
    assert result["query"] == {"match_all": {}}
