from edr_backend.ai.rag.retriever import load_corpus, retrieve


def test_load_corpus_finds_all_docs():
    docs = load_corpus()
    ids = {d["doc_id"] for d in docs}
    assert "T1059" in ids
    assert "T1571" in ids
    assert "runbook" in ids
    assert len(docs) >= 10


def test_load_corpus_titles_are_readable():
    docs = load_corpus()
    reverse_shell = next(d for d in docs if d["doc_id"] == "T1571")
    assert "Non-Standard Port" in reverse_shell["title"]


def test_retrieve_reverse_shell_query_finds_relevant_docs():
    results = retrieve("reverse shell netcat outbound connection")
    ids = {d["doc_id"] for d in results}
    assert "T1571" in ids


def test_retrieve_empty_query_returns_nothing():
    assert retrieve("") == []


def test_retrieve_respects_k():
    results = retrieve("technique detection rule host process", k=2)
    assert len(results) <= 2
