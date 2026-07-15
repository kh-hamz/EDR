"""ATT&CK tagging: pulled directly from each Sigma rule's own `tags:` field
(the standard `attack.txxxx` / `attack.<tactic>` convention) rather than a
separate rule_id -> technique mapping file. A parallel mapping file would
just be a second place the same information could drift out of sync with
the rules themselves.
"""

import re

_TECHNIQUE_RE = re.compile(r"^t(\d{4}(?:\.\d{3})?)$")


def parse_attack_tags(tags: list[str]) -> tuple[str | None, str | None]:
    """Returns (tactic, technique_id) parsed from Sigma tags like
    'attack.persistence' and 'attack.t1053.003'. Takes the first match of
    each kind; our rules are written one-technique-per-rule."""
    tactic: str | None = None
    technique_id: str | None = None

    for tag in tags:
        body = str(tag).lower().removeprefix("attack.")
        match = _TECHNIQUE_RE.match(body)
        if match:
            if technique_id is None:
                technique_id = "T" + match.group(1)
        elif tactic is None:
            tactic = body

    return tactic, technique_id


def parse_all_attack_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    """Every (tactics, technique_ids) on a rule, order-preserving and
    de-duplicated. parse_attack_tags keeps only the primary of each because
    an alert row stores one technique; the coverage heatmap needs the full
    set, since a single rule often spans several techniques (a reverse shell
    is both T1059 and T1571)."""
    tactics: list[str] = []
    techniques: list[str] = []

    for tag in tags:
        body = str(tag).lower().removeprefix("attack.")
        match = _TECHNIQUE_RE.match(body)
        if match:
            technique_id = "T" + match.group(1)
            if technique_id not in techniques:
                techniques.append(technique_id)
        elif body not in tactics:
            tactics.append(body)

    return tactics, techniques
