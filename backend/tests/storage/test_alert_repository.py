import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from edr_backend.core.db import Base
from edr_backend.storage.repositories import AlertRepository


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    yield session
    session.close()


def _make(repo, event_id="e1", rule_id="r1"):
    return repo.create_if_new(
        event_id=event_id,
        rule_id=rule_id,
        title="Reverse shell via netcat",
        severity="critical",
        hostname="victim-01",
        tactic="execution",
        technique_id="T1059",
    )


def test_create_new_alert(db):
    repo = AlertRepository(db)
    alert = _make(repo)
    assert alert is not None
    assert alert.status == "open"
    assert len(repo.list_all()) == 1


def test_duplicate_rule_and_event_is_a_noop(db):
    repo = AlertRepository(db)
    first = _make(repo)
    second = _make(repo)
    assert first is not None
    assert second is None
    assert len(repo.list_all()) == 1


def test_same_event_different_rule_creates_separate_alert(db):
    repo = AlertRepository(db)
    _make(repo, event_id="e1", rule_id="r1")
    _make(repo, event_id="e1", rule_id="r2")
    assert len(repo.list_all()) == 2


def test_list_all_filters_by_status_and_severity(db):
    repo = AlertRepository(db)
    a1 = _make(repo, event_id="e1", rule_id="r1")
    _make(repo, event_id="e2", rule_id="r2")
    repo.update_status(a1.id, "closed")

    assert len(repo.list_all(status="open")) == 1
    assert len(repo.list_all(status="closed")) == 1
    assert len(repo.list_all(severity="critical")) == 2


def test_update_status_unknown_id_returns_none(db):
    repo = AlertRepository(db)
    assert repo.update_status(999, "closed") is None
