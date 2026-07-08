import pytest

from edr_backend.response.actions import ActionError, VALID_ACTIONS, validate


def test_valid_actions_set():
    assert VALID_ACTIONS == {"kill_process", "isolate_host", "unisolate_host", "quarantine_file"}


def test_kill_process_requires_int_pid():
    assert validate("kill_process", {"pid": 1234}) == {"pid": 1234}


def test_kill_process_rejects_missing_pid():
    with pytest.raises(ActionError, match="requires param 'pid'"):
        validate("kill_process", {})


def test_kill_process_rejects_non_int_pid():
    with pytest.raises(ActionError, match="must be int"):
        validate("kill_process", {"pid": "1234"})


def test_kill_process_rejects_bool_pid():
    # bool is an int subclass; pid=True must not sneak through
    with pytest.raises(ActionError, match="must be int"):
        validate("kill_process", {"pid": True})


def test_isolate_host_takes_no_params():
    assert validate("isolate_host", {}) == {}


def test_extra_params_are_rejected():
    with pytest.raises(ActionError, match="unexpected params"):
        validate("isolate_host", {"pid": 1})


def test_quarantine_file_requires_path_string():
    assert validate("quarantine_file", {"path": "/tmp/x"}) == {"path": "/tmp/x"}


def test_unknown_action_rejected():
    with pytest.raises(ActionError, match="unknown action"):
        validate("format_disk", {})
