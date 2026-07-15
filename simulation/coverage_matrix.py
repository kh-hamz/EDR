"""ATT&CK coverage heatmap generator (roadmap Phase 7).

Reads the real Sigma rules under detection-content/sigma/ and reports which
MITRE ATT&CK techniques the EDR detects. The rules' own `attack.*` tags are
the single source of truth (same principle as attack_map.py): there is no
separate mapping file to drift out of sync.

Two outputs, both derived from the same data:
  - a Markdown matrix grouped by ATT&CK tactic (printed to stdout), and
  - a MITRE ATT&CK Navigator layer (JSON), the standard format you upload to
    the Navigator to render the coloured technique matrix.

Detection *validation* (did an Atomic Red Team test actually fire the rule)
is a separate axis that needs the victim VM and a real run; that is recorded
by --results once such a run exists. Without it the layer reflects rule
coverage only, which is the honest state until sensors are live.

Run:  .venv/bin/python -m simulation.coverage_matrix
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from edr_backend.detection.attack_map import parse_all_attack_tags
from edr_backend.detection.sigma_engine import load_sigma_collection

# Severity -> Navigator score (0-100) and the human label used in the table.
# The highest-severity rule covering a technique sets that technique's colour.
_SEVERITY_SCORE = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}

# ATT&CK kill-chain order for the ones our scope touches; any tactic not
# listed is appended alphabetically so a new rule can never silently vanish.
_TACTIC_ORDER = [
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "command-and-control",
]

_DEFAULT_LAYER = Path(__file__).resolve().parent / "attack_navigator_layer.json"


@dataclass(frozen=True)
class RuleTags:
    """The slice of a Sigma rule the heatmap cares about."""

    title: str
    severity: str
    tactics: tuple[str, ...]
    techniques: tuple[str, ...]


@dataclass(frozen=True)
class TechniqueCoverage:
    """One ATT&CK technique and every rule that detects it."""

    technique_id: str
    tactics: tuple[str, ...]
    severity: str  # highest severity among the covering rules
    rules: tuple[str, ...]  # rule titles, in load order


def load_rule_tags() -> list[RuleTags]:
    """Read the on-disk Sigma rules into RuleTags (title/severity/tags only)."""
    collection = load_sigma_collection()
    rules: list[RuleTags] = []
    for rule in collection.rules:
        tactics, techniques = parse_all_attack_tags([str(t) for t in rule.tags])
        rules.append(
            RuleTags(
                title=rule.title,
                severity=rule.level.name.lower() if rule.level else "info",
                tactics=tuple(tactics),
                techniques=tuple(techniques),
            )
        )
    return rules


def build_coverage(rules: list[RuleTags]) -> list[TechniqueCoverage]:
    """Aggregate rules by technique: union the tactics, keep the highest
    severity, and list every covering rule. Sorted by technique ID so the
    output is stable across runs."""
    tactics: dict[str, list[str]] = {}
    severities: dict[str, str] = {}
    titles: dict[str, list[str]] = {}

    for rule in rules:
        for technique in rule.techniques:
            for tactic in rule.tactics:
                if tactic not in tactics.setdefault(technique, []):
                    tactics[technique].append(tactic)
            if rule.title not in titles.setdefault(technique, []):
                titles[technique].append(rule.title)
            current = severities.get(technique)
            if current is None or _SEVERITY_SCORE[rule.severity] > _SEVERITY_SCORE[current]:
                severities[technique] = rule.severity

    return [
        TechniqueCoverage(
            technique_id=technique,
            tactics=tuple(tactics[technique]),
            severity=severities[technique],
            rules=tuple(titles[technique]),
        )
        for technique in sorted(titles)
    ]


def _tactic_sort_key(tactic: str) -> tuple[int, str]:
    return (_TACTIC_ORDER.index(tactic), "") if tactic in _TACTIC_ORDER else (len(_TACTIC_ORDER), tactic)


def to_navigator_layer(coverage: list[TechniqueCoverage], name: str) -> dict:
    """Build a MITRE ATT&CK Navigator layer (schema 4.5). One entry per
    technique with no `tactic` field: a rule tags several tactics and several
    techniques without pairing them, so pinning a technique to a rule tactic
    would mis-file it (T1059 under command-and-control). Omitting the tactic
    lets the Navigator colour each technique under its own correct column(s)."""
    techniques = [
        {
            "techniqueID": cov.technique_id,
            "score": _SEVERITY_SCORE[cov.severity],
            "comment": "; ".join(cov.rules),
            "enabled": True,
        }
        for cov in coverage
    ]

    return {
        "name": name,
        "domain": "enterprise-attack",
        "description": "EDR Sigma-rule detection coverage. Score = highest "
        "severity of the rules covering the technique.",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe0e0", "#ff6666", "#b30000"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "critical rule", "color": "#b30000"},
            {"label": "high rule", "color": "#ff6666"},
            {"label": "medium/low rule", "color": "#ffe0e0"},
        ],
    }


def to_markdown(coverage: list[TechniqueCoverage]) -> str:
    """A flat coverage matrix, one row per technique. The Tactics column lists
    the ATT&CK tactics the covering rules are tagged with (rule metadata), not
    a claim that the technique itself belongs to each; techniques are the key,
    so the table is sorted by technique ID."""
    technique_count = len(coverage)
    rule_count = len({r for c in coverage for r in c.rules})

    lines = [
        "# ATT&CK Detection Coverage",
        "",
        f"{technique_count} techniques covered by {rule_count} Sigma rules.",
        "",
        "| Technique | Tactics | Severity | Detecting rules |",
        "|---|---|---|---|",
    ]
    for cov in coverage:
        tactics = ", ".join(sorted(cov.tactics, key=_tactic_sort_key))
        lines.append(f"| {cov.technique_id} | {tactics} | {cov.severity} | {'; '.join(cov.rules)} |")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the ATT&CK coverage heatmap.")
    parser.add_argument(
        "--output",
        type=Path,
        default=_DEFAULT_LAYER,
        help="path for the ATT&CK Navigator layer JSON (default: simulation/attack_navigator_layer.json)",
    )
    parser.add_argument(
        "--name",
        default="EDR Detection Coverage",
        help="layer name shown in the Navigator",
    )
    args = parser.parse_args(argv)

    coverage = build_coverage(load_rule_tags())
    if not coverage:
        print("No Sigma rules found under detection-content/sigma/.")
        return 1

    args.output.write_text(json.dumps(to_navigator_layer(coverage, args.name), indent=2))
    print(to_markdown(coverage))
    print(f"\nNavigator layer written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
