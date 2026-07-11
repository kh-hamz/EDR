from edr_backend.ai.rag import explain as explain_module


def test_explain_with_direct_technique_id(monkeypatch):
    monkeypatch.setattr(explain_module.llm_client, "complete", lambda system, user, max_tokens=2048: "answer")
    result = explain_module.explain("T1571")
    assert result["sources"] == ["T1571"]
    assert result["answer"] == "answer"


def test_explain_with_free_text_falls_back_to_retrieval(monkeypatch):
    monkeypatch.setattr(explain_module.llm_client, "complete", lambda system, user, max_tokens=2048: "answer")
    result = explain_module.explain("how does the system handle log clearing")
    assert "T1070" in result["sources"]


def test_explain_with_no_match_skips_llm_call(monkeypatch):
    called = []
    monkeypatch.setattr(explain_module.llm_client, "complete", lambda *a, **k: called.append(1))
    result = explain_module.explain("xyzzy plugh")
    assert result["sources"] == []
    assert called == []
