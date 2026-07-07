"""Standalone YARA engine: compiles rules from detection-content/yara/ and
exposes scan_file() for scanning a file's byte content on the backend host.

Not wired to live agent file_events: the agent only ever ships file
*metadata* (path/action/hash/size), never content (see
agent/edr_agent/normalizer - Phase 1 scope), so there's nothing to scan from
live telemetry today. This is what Phase 5's quarantine flow will call once a
suspicious file actually lands on the backend host; for now it's usable
directly, e.g. for manual triage.
"""

from pathlib import Path

import yara

_YARA_DIR = Path(__file__).resolve().parents[3] / "detection-content" / "yara"

_rules: yara.Rules | None = None


def _compiled_rules() -> yara.Rules | None:
    global _rules
    if _rules is None:
        files = {f.stem: str(f) for f in sorted(_YARA_DIR.glob("*.yar"))}
        _rules = yara.compile(filepaths=files) if files else None
    return _rules


def scan_file(path: str) -> list[str]:
    """Returns the names of every YARA rule that matched, or [] if none did."""
    rules = _compiled_rules()
    if rules is None:
        return []
    return [match.rule for match in rules.match(path)]
