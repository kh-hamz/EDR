import pytest

from edr_agent.config import AgentSettings
from edr_agent.responder import actions
from edr_agent.responder.poller import Responder


@pytest.fixture
def responder():
    settings = AgentSettings(
        api_token="secret",
        backend_url="http://backend-host:8000",
        data_dir="/var/lib/edr-agent",
    )
    return Responder(settings, agent_id="agent-1")


def test_backend_host_extracted_for_isolation(responder):
    assert responder._backend_host == "backend-host"


def test_execute_kill_process(responder, monkeypatch):
    called = {}

    def fake_kill(pid):
        called["pid"] = pid
        return "ok"

    monkeypatch.setattr(actions, "kill_process", fake_kill)
    assert responder._execute("kill_process", {"pid": 4242}) == "ok"
    assert called["pid"] == 4242


def test_execute_isolate_passes_backend_host(responder, monkeypatch):
    called = {}

    def fake_isolate(host):
        called["host"] = host
        return "isolated"

    monkeypatch.setattr(actions, "isolate_host", fake_isolate)
    responder._execute("isolate_host", {})
    assert called["host"] == "backend-host"


def test_execute_quarantine_uses_data_dir(responder, monkeypatch):
    called = {}
    monkeypatch.setattr(
        actions, "quarantine_file",
        lambda path, qdir: called.update(path=path, qdir=qdir) or "quarantined",
    )
    responder._execute("quarantine_file", {"path": "/tmp/evil"})
    assert called == {"path": "/tmp/evil", "qdir": "/var/lib/edr-agent/quarantine"}


def test_execute_unknown_action_raises(responder):
    with pytest.raises(ValueError, match="unknown action"):
        responder._execute("format_disk", {})


def test_handle_acks_success(responder, monkeypatch):
    monkeypatch.setattr(actions, "isolate_host", lambda host: "isolated")
    acks = []
    monkeypatch.setattr(responder, "_ack", lambda cid, status, result: acks.append((cid, status, result)))

    responder._handle({"id": 7, "action": "isolate_host", "params": {}})
    assert acks == [(7, "succeeded", "isolated")]


def test_handle_acks_failure_on_action_failed(responder, monkeypatch):
    def boom(pid):
        raise actions.ActionFailed("not permitted")

    monkeypatch.setattr(actions, "kill_process", boom)
    acks = []
    monkeypatch.setattr(responder, "_ack", lambda cid, status, result: acks.append((cid, status, result)))

    responder._handle({"id": 8, "action": "kill_process", "params": {"pid": 1}})
    assert acks[0][1] == "failed"
    assert "not permitted" in acks[0][2]


def test_handle_acks_failure_on_unknown_action(responder, monkeypatch):
    acks = []
    monkeypatch.setattr(responder, "_ack", lambda cid, status, result: acks.append((cid, status, result)))
    responder._handle({"id": 9, "action": "bogus", "params": {}})
    assert acks[0][1] == "failed"
