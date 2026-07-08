from edr_backend.storage.repositories import CommandRepository


def _cmd(repo, agent_id="agent-1", action="isolate_host"):
    return repo.create(agent_id=agent_id, hostname="victim-01", action=action, params={})


def test_claim_pending_moves_to_dispatched(db):
    repo = CommandRepository(db)
    _cmd(repo)
    claimed = repo.claim_pending("agent-1")
    assert len(claimed) == 1
    assert claimed[0].status == "dispatched"
    assert claimed[0].dispatched_at is not None
    # a second poll before ack returns nothing
    assert repo.claim_pending("agent-1") == []


def test_claim_pending_is_scoped_to_agent(db):
    repo = CommandRepository(db)
    _cmd(repo, agent_id="agent-1")
    _cmd(repo, agent_id="agent-2")
    assert len(repo.claim_pending("agent-1")) == 1


def test_complete_sets_result_and_status(db):
    repo = CommandRepository(db)
    command = _cmd(repo)
    repo.claim_pending("agent-1")
    done = repo.complete(command.id, "succeeded", "killed pid 42")
    assert done.status == "succeeded"
    assert done.result == "killed pid 42"
    assert done.completed_at is not None


def test_complete_unknown_id_returns_none(db):
    assert CommandRepository(db).complete(999, "succeeded", None) is None


def test_list_all_filters(db):
    repo = CommandRepository(db)
    _cmd(repo, action="isolate_host")
    c2 = _cmd(repo, action="kill_process")
    repo.claim_pending("agent-1")
    repo.complete(c2.id, "failed", "boom")
    assert len(repo.list_all(status="failed")) == 1
    assert len(repo.list_all(hostname="victim-01")) == 2
