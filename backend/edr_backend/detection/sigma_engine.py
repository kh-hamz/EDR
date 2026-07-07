"""Load Sigma rules from detection-content/sigma/ and compile each to an
OpenSearch Lucene query string via pySigma. Our schema's field names (e.g.
process.name, inventory.query_name) are used directly in the rules, so no
Sigma processing pipeline (field renaming) is needed - just direct passthrough."""

from dataclasses import dataclass
from pathlib import Path

from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.collection import SigmaCollection

from .attack_map import parse_attack_tags

_SIGMA_DIR = Path(__file__).resolve().parents[3] / "detection-content" / "sigma"


@dataclass(frozen=True)
class CompiledRule:
    rule_id: str
    title: str
    severity: str
    tactic: str | None
    technique_id: str | None
    query: str


def load_rules() -> list[CompiledRule]:
    files = sorted(_SIGMA_DIR.glob("*.yml"))
    if not files:
        return []

    collection = SigmaCollection.from_yaml("\n---\n".join(f.read_text() for f in files))
    backend = OpensearchLuceneBackend()

    compiled = []
    for rule in collection.rules:
        query = backend.convert(SigmaCollection([rule]))[0]
        tactic, technique_id = parse_attack_tags([str(t) for t in rule.tags])
        compiled.append(
            CompiledRule(
                rule_id=str(rule.id),
                title=rule.title,
                severity=rule.level.name.lower(),
                tactic=tactic,
                technique_id=technique_id,
                query=query,
            )
        )
    return compiled
