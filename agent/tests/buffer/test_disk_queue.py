from edr_agent.buffer import disk_queue
from edr_agent.buffer.disk_queue import DiskQueue


def test_fifo_and_commit(tmp_path):
    q = DiskQueue(tmp_path)
    for i in range(5):
        q.put({"n": i})

    items, cursor = q.read_batch(3)
    assert [it["n"] for it in items] == [0, 1, 2]

    # uncommitted read is repeatable
    items_again, _ = q.read_batch(3)
    assert [it["n"] for it in items_again] == [0, 1, 2]

    q.commit(cursor)
    items, cursor = q.read_batch(10)
    assert [it["n"] for it in items] == [3, 4]
    q.commit(cursor)

    items, cursor = q.read_batch(10)
    assert items == [] and cursor is None


def test_survives_restart(tmp_path):
    q = DiskQueue(tmp_path)
    for i in range(4):
        q.put({"n": i})
    items, cursor = q.read_batch(2)
    q.commit(cursor)

    q2 = DiskQueue(tmp_path)
    items, _ = q2.read_batch(10)
    assert [it["n"] for it in items] == [2, 3]

    q2.put({"n": 99})
    items, _ = q2.read_batch(10)
    assert [it["n"] for it in items] == [2, 3, 99]


def test_segment_rotation_and_cleanup(tmp_path, monkeypatch):
    monkeypatch.setattr(disk_queue, "MAX_SEGMENT_LINES", 2)
    q = DiskQueue(tmp_path)
    for i in range(5):
        q.put({"n": i})
    assert len(list(tmp_path.glob("seg-*.jsonl"))) == 3

    items, cursor = q.read_batch(10)
    assert [it["n"] for it in items] == [0, 1, 2, 3, 4]
    q.commit(cursor)
    # fully consumed older segments are deleted
    assert len(list(tmp_path.glob("seg-*.jsonl"))) == 1

    items, _ = q.read_batch(10)
    assert items == []
