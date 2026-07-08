from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from edr_backend.core.db import Base
from edr_backend.storage.models import AgentRecord, Alert


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    yield session
    session.close()


@pytest.fixture
def enrolled_host(db):
    agent = AgentRecord(
        agent_id="agent-1",
        hostname="victim-01",
        os="linux",
        ip="10.0.0.9",
        enrolled_at=datetime.now(timezone.utc),
    )
    db.add(agent)
    db.commit()
    return agent


@pytest.fixture
def make_alert(db):
    """Factory fixture: create an alert row. Returned as a fixture (not an
    importable helper) because rootless pytest test dirs have no package to
    relative-import from."""
    def _make(event_id="e1", rule_id="r1", hostname="victim-01", severity="critical"):
        alert = Alert(
            event_id=event_id, rule_id=rule_id, title="Reverse shell via netcat",
            severity=severity, hostname=hostname, tactic="execution", technique_id="T1059",
            created_at=datetime.now(timezone.utc), status="open",
        )
        db.add(alert)
        db.commit()
        return alert

    return _make
