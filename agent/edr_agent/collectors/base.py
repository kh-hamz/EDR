"""Collector base: tail a JSON-lines log file, yielding parsed dicts.

Both Falco (file_output) and osquery (filesystem logger) write JSON lines to
a log file, so one tailer covers both. It handles the two things that break
naive `readline` loops:

- rotation: the file is renamed/recreated (logrotate), detected via inode change
- truncation: the file shrinks in place, detected via size < current offset

Tailing starts at the end of the file: on agent (re)start we only ship new
events. Events emitted while the agent is down are a documented gap for now;
closing it needs persisted read offsets, which can come later if it matters.
"""

import json
import logging
import os
import threading
from abc import ABC
from typing import Iterator

log = logging.getLogger(__name__)

_POLL_SECONDS = 0.5


class Collector(ABC):
    observer: str  # matches schema Observer literal

    def __init__(self, path: str):
        self.path = path

    def stream(self, stop: threading.Event) -> Iterator[dict]:
        for line in self._tail(stop):
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                log.warning("%s: skipping malformed line: %.120s", self.observer, line)

    def _tail(self, stop: threading.Event) -> Iterator[str]:
        f = None
        inode = None
        while not stop.is_set():
            if f is None:
                try:
                    f = open(self.path, "rb")
                    inode = os.fstat(f.fileno()).st_ino
                    f.seek(0, os.SEEK_END)
                    log.info("%s: tailing %s", self.observer, self.path)
                except FileNotFoundError:
                    stop.wait(_POLL_SECONDS)
                    continue

            line = f.readline()
            if line:
                if line.endswith(b"\n"):
                    yield line.decode("utf-8", errors="replace")
                else:
                    # partial line mid-write: rewind and retry next poll
                    f.seek(-len(line), os.SEEK_CUR)
                    stop.wait(_POLL_SECONDS)
                continue

            try:
                st = os.stat(self.path)
                rotated = st.st_ino != inode or st.st_size < f.tell()
            except FileNotFoundError:
                rotated = True
            if rotated:
                f.close()
                f = None
            else:
                stop.wait(_POLL_SECONDS)

        if f is not None:
            f.close()
