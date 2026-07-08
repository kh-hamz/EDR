import pytest

from edr_backend.response.issuer import IssueError, issue_command
from edr_backend.storage.repositories import CommandRepository


def test_issue_manual_command(db, enrolled_host):
    command = issue_command(db, "victim-01", "isolate_host", {})
    assert command.agent_id == "agent-1"
    assert command.status == "pending"
    assert command.action == "isolate_host"


def test_issue_to_unknown_host_raises(db):
    with pytest.raises(IssueError, match="no enrolled host"):
        issue_command(db, "ghost", "isolate_host", {})


def test_issue_invalid_action_raises(db, enrolled_host):
    with pytest.raises(IssueError, match="unknown action"):
        issue_command(db, "victim-01", "format_disk", {})


def test_issue_bad_params_raises(db, enrolled_host):
    with pytest.raises(IssueError, match="requires param 'pid'"):
        issue_command(db, "victim-01", "kill_process", {})


def test_duplicate_source_alert_raises(db, enrolled_host, make_alert):
    alert = make_alert()
    issue_command(db, "victim-01", "kill_process", {"pid": 42}, source_alert_id=alert.id)
    with pytest.raises(IssueError, match="already exists for alert"):
        issue_command(db, "victim-01", "kill_process", {"pid": 42}, source_alert_id=alert.id)
    assert len(CommandRepository(db).list_all()) == 1


def test_manual_commands_do_not_collide(db, enrolled_host):
    # both have source_alert_id=None; NULLs are distinct under the unique constraint
    issue_command(db, "victim-01", "isolate_host", {})
    issue_command(db, "victim-01", "isolate_host", {})
    assert len(CommandRepository(db).list_all()) == 2
