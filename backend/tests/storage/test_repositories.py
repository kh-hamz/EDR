import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from edr_backend.core.db import Base
from edr_backend.storage.repositories import AgentRepository


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    yield session
    session.close()


def test_upsert_creates_new_agent(db):
    repo = AgentRepository(db)
    agent = repo.upsert(agent_id="a1", hostname="victim-01", os="linux", ip="10.0.0.21")
    assert agent.agent_id == "a1"
    assert repo.get_by_hostname("victim-01").agent_id == "a1"


def test_upsert_same_hostname_keeps_identity(db):
    repo = AgentRepository(db)
    first = repo.upsert(agent_id="a1", hostname="victim-01", os="linux", ip="10.0.0.21")
    second = repo.upsert(agent_id="a2", hostname="victim-01", os="linux", ip="10.0.0.99")

    # re-enrollment from the same hostname keeps the original agent_id, only
    # os/ip get refreshed, so reinstalling the agent never creates a duplicate host
    assert second.agent_id == first.agent_id
    assert second.ip == "10.0.0.99"
    assert len(repo.list_all()) == 1


def test_list_all_sorted_by_hostname(db):
    repo = AgentRepository(db)
    repo.upsert(agent_id="a1", hostname="zeta", os="linux", ip=None)
    repo.upsert(agent_id="a2", hostname="alpha", os="linux", ip=None)
    assert [a.hostname for a in repo.list_all()] == ["alpha", "zeta"]


def test_touch_last_seen_updates_known_agents_only(db):
    repo = AgentRepository(db)
    repo.upsert(agent_id="a1", hostname="victim-01", os="linux", ip=None)
    assert repo.get_by_hostname("victim-01").last_seen is None

    repo.touch_last_seen({"a1", "unknown-agent-id"})
    assert repo.get_by_hostname("victim-01").last_seen is not None
