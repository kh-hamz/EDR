from edr_backend.response import playbook
from edr_backend.storage.repositories import CommandRepository

RULE_ID = playbook._REVERSE_SHELL_RULE_ID


def _event(event_id, pid):
    return {"event_id": event_id, "process": {"pid": pid}}


def test_reverse_shell_alert_issues_kill(db, enrolled_host, make_alert, monkeypatch):
    alert = make_alert(event_id="ev-1", rule_id=RULE_ID)
    monkeypatch.setattr(playbook, "get_events_by_ids", lambda ids: [_event("ev-1", 4242)])

    assert playbook.run_playbooks(db) == 1
    commands = CommandRepository(db).list_all()
    assert len(commands) == 1
    assert commands[0].action == "kill_process"
    assert commands[0].params == {"pid": 4242}
    assert commands[0].source_alert_id == alert.id


def test_playbook_is_idempotent(db, enrolled_host, make_alert, monkeypatch):
    make_alert(event_id="ev-1", rule_id=RULE_ID)
    monkeypatch.setattr(playbook, "get_events_by_ids", lambda ids: [_event("ev-1", 4242)])

    assert playbook.run_playbooks(db) == 1
    # second run: the alert already has a command, so nothing new is issued
    assert playbook.run_playbooks(db) == 0
    assert len(CommandRepository(db).list_all()) == 1


def test_other_rules_are_ignored(db, enrolled_host, make_alert, monkeypatch):
    make_alert(event_id="ev-1", rule_id="some-other-rule")
    monkeypatch.setattr(playbook, "get_events_by_ids", lambda ids: [_event("ev-1", 4242)])

    assert playbook.run_playbooks(db) == 0
    assert CommandRepository(db).list_all() == []


def test_event_without_pid_is_skipped(db, enrolled_host, make_alert, monkeypatch):
    make_alert(event_id="ev-1", rule_id=RULE_ID)
    monkeypatch.setattr(playbook, "get_events_by_ids", lambda ids: [{"event_id": "ev-1", "process": {}}])

    assert playbook.run_playbooks(db) == 0
    assert CommandRepository(db).list_all() == []
