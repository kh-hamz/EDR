"""Disk-backed FIFO queue so events survive backend downtime and agent restarts.

Layout in the spool directory:
    seg-0000000001.jsonl   append-only segments, one JSON event per line
    seg-0000000002.jsonl   (active segment = highest number)
    cursor.json            {"segment": "...", "line": N} = consumed up to here

Writer appends to the active segment, rotating at MAX_SEGMENT_LINES.
Reader (the shipper) calls read_batch() then commit() after the backend acks;
commit persists the cursor and deletes fully-consumed older segments. Crash
between ack and commit re-ships a batch, which is safe because the backend
indexes by event_id (idempotent).
"""

import json
import os
import threading
from pathlib import Path

MAX_SEGMENT_LINES = 5000

Cursor = tuple[str, int]  # (segment filename, lines consumed)


class DiskQueue:
    def __init__(self, spool_dir: str | Path):
        self.dir = Path(spool_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

        segments = self._segments()
        if segments:
            active = segments[-1]
            with open(self.dir / active, "rb") as f:
                self._active_lines = sum(1 for _ in f)
            self._active = active
        else:
            self._active = self._segment_name(1)
            self._active_lines = 0

    def put(self, item: dict) -> None:
        line = json.dumps(item, separators=(",", ":")) + "\n"
        with self._lock:
            if self._active_lines >= MAX_SEGMENT_LINES:
                seq = int(self._active.split("-")[1].split(".")[0]) + 1
                self._active = self._segment_name(seq)
                self._active_lines = 0
            with open(self.dir / self._active, "a", encoding="utf-8") as f:
                f.write(line)
            self._active_lines += 1

    def read_batch(self, max_items: int) -> tuple[list[dict], Cursor | None]:
        """Read up to max_items unconsumed events. Does not advance state;
        call commit(cursor) once the batch is safely delivered."""
        with self._lock:
            cur_seg, cur_line = self._load_cursor()
            items: list[dict] = []
            cursor: Cursor | None = None

            for seg in self._segments():
                if cur_seg is not None and seg < cur_seg:
                    continue
                skip = cur_line if seg == cur_seg else 0
                with open(self.dir / seg, encoding="utf-8") as f:
                    for i, line in enumerate(f):
                        if i < skip:
                            continue
                        items.append(json.loads(line))
                        cursor = (seg, i + 1)
                        if len(items) >= max_items:
                            return items, cursor
            return items, cursor

    def commit(self, cursor: Cursor) -> None:
        with self._lock:
            seg, line = cursor
            tmp = self.dir / "cursor.json.tmp"
            tmp.write_text(json.dumps({"segment": seg, "line": line}))
            os.replace(tmp, self.dir / "cursor.json")
            for old in self._segments():
                if old < seg:
                    (self.dir / old).unlink()

    def _load_cursor(self) -> tuple[str | None, int]:
        path = self.dir / "cursor.json"
        if not path.exists():
            return None, 0
        data = json.loads(path.read_text())
        return data["segment"], data["line"]

    def _segments(self) -> list[str]:
        return sorted(p.name for p in self.dir.glob("seg-*.jsonl"))

    @staticmethod
    def _segment_name(seq: int) -> str:
        return f"seg-{seq:010d}.jsonl"
