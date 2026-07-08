from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from edr_backend.core.db import Base
from edr_backend.correlation.grouper import correlate_alerts
from edr_backend.storage.models import Alert, Incident
from edr_backend.storage.repositories import IncidentRepository

T0 = datetime(2026, 7, 8, 10, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    yield session
    session.close()


def _alert(db, event_id, created_at, hostname="victim-01", severity="medium",
           rule_id="r1", title="Suspicious shell"):
    alert = Alert(
        event_id=event_id, rule_id=rule_id, title=title, severity=severity,
        hostname=hostname, tactic="execution", technique_id="T1059",
        created_at=created_at, status="open",
    )
    db.add(alert)
    db.commit()
    return alert


def test_close_alerts_on_same_host_share_one_incident(db):
    _alert(db, "e1", T0)
    _alert(db, "e2", T0 + timedelta(minutes=5), rule_id="r2")

    assert correlate_alerts(db) == 2
    incidents = db.query(Incident).all()
    assert len(incidents) == 1
    # sqlite returns naive datetimes; normalize before comparing (Postgres keeps tz)
    assert incidents[0].first_alert_at.replace(tzinfo=timezone.utc) == T0
    assert incidents[0].last_alert_at.replace(tzinfo=timezone.utc) == T0 + timedelta(minutes=5)
    assert len(IncidentRepository(db).alerts_for(incidents[0].id)) == 2


def test_gap_beyond_window_starts_new_incident(db):
    _alert(db, "e1", T0)
    _alert(db, "e2", T0 + timedelta(minutes=45), rule_id="r2")

    correlate_alerts(db)
    assert db.query(Incident).count() == 2


def test_different_hosts_never_share_an_incident(db):
    _alert(db, "e1", T0, hostname="victim-01")
    _alert(db, "e2", T0 + timedelta(minutes=1), hostname="victim-02")

    correlate_alerts(db)
    assert db.query(Incident).count() == 2


def test_severity_escalates_to_max(db):
    _alert(db, "e1", T0, severity="low")
    _alert(db, "e2", T0 + timedelta(minutes=1), rule_id="r2", severity="critical")
    _alert(db, "e3", T0 + timedelta(minutes=2), rule_id="r3", severity="medium")

    correlate_alerts(db)
    incident = db.query(Incident).one()
    assert incident.severity == "critical"


def test_rerun_is_idempotent(db):
    _alert(db, "e1", T0)
    assert correlate_alerts(db) == 1
    assert correlate_alerts(db) == 0
    assert db.query(Incident).count() == 1


def test_closed_incident_does_not_absorb_new_alerts(db):
    _alert(db, "e1", T0)
    correlate_alerts(db)
    incident = db.query(Incident).one()
    IncidentRepository(db).update_status(incident.id, "closed")

    _alert(db, "e2", T0 + timedelta(minutes=1), rule_id="r2")
    correlate_alerts(db)
    assert db.query(Incident).count() == 2


def test_incident_title_comes_from_first_alert(db):
    _alert(db, "e1", T0, title="Reverse shell via netcat")
    _alert(db, "e2", T0 + timedelta(minutes=1), rule_id="r2", title="Credential file access")

    correlate_alerts(db)
    assert db.query(Incident).one().title == "Reverse shell via netcat"
