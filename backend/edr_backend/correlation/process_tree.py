"""Rebuilds process trees from process_create events.

Pure function over event dicts, so it unit-tests without OpenSearch. Parents
that never produced a create event inside the window (e.g. a long-running
sshd) still appear as synthetic root nodes built from the child's `parent`
info; they are recognizable by event_id=None.

Known limitation (accepted at lab scale): PID reuse inside one window is not
disambiguated - a reused pid keeps a single node with the latest identity.
"""


def _new_node(pid: int) -> dict:
    return {
        "pid": pid,
        "name": None,
        "cmdline": None,
        "user": None,
        "time": None,
        "event_id": None,
        "children": [],
    }


def build_process_tree(events: list[dict]) -> list[dict]:
    """events: process_create event dicts (any order). Returns root nodes,
    each a JSON-ready dict with nested `children`."""
    nodes: dict[int, dict] = {}
    parent_of: dict[int, int] = {}

    for event in sorted(events, key=lambda e: e["time"]):
        proc = event.get("process") or {}
        pid = proc.get("pid")
        if pid is None:
            continue

        node = nodes.setdefault(pid, _new_node(pid))
        node["name"] = proc.get("name")
        node["cmdline"] = proc.get("cmdline")
        node["user"] = (proc.get("user") or {}).get("name")
        node["time"] = event["time"]
        node["event_id"] = event["event_id"]

        parent_info = proc.get("parent") or {}
        ppid = proc.get("ppid")
        if ppid is None:
            ppid = parent_info.get("pid")
        if ppid is None or ppid == pid or pid in parent_of:
            continue

        parent = nodes.setdefault(ppid, _new_node(ppid))
        # A synthetic parent (no create event of its own) at least gets the
        # name/cmdline the child observed.
        if parent["event_id"] is None and parent_info.get("name"):
            parent["name"] = parent_info.get("name")
            parent["cmdline"] = parent_info.get("cmdline")
        parent["children"].append(node)
        parent_of[pid] = ppid

    return [node for pid, node in nodes.items() if pid not in parent_of]
