"""Runs every compiled Sigma rule as an OpenSearch query over a trailing time
window and turns new matches into alerts. Re-querying a trailing window
(rather than tracking a precise per-rule cursor) tolerates a missed tick
without losing detections; AlertRepository.create_if_new() de-dupes on
(rule_id, event_id) so re-seeing the same event is a no-op, not a duplicate.
"""

import logging
from datetime import datetime, timezone

from ..core.db import SessionLocal
from ..storage.opensearch_client import search_rule_matches
from ..storage.repositories import AlertRepository
from .sigma_engine import load_rules

log = logging.getLogger(__name__)


def run_detection(since: datetime) -> int:
    rules = load_rules()
    if not rules:
        return 0

    since_iso = since.astimezone(timezone.utc).isoformat()
    created = 0

    db = SessionLocal()
    try:
        repo = AlertRepository(db)
        for rule in rules:
            for source in search_rule_matches(rule.query, since_iso):
                alert = repo.create_if_new(
                    event_id=source["event_id"],
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    hostname=source["host"]["hostname"],
                    tactic=rule.tactic,
                    technique_id=rule.technique_id,
                )
                if alert is not None:
                    created += 1
                    log.info(
                        "alert: %s on %s (event %s)",
                        rule.title,
                        source["host"]["hostname"],
                        source["event_id"],
                    )
    finally:
        db.close()

    return created
