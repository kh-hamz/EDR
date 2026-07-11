"""Explain this technique" panel: retrieve grounding context from the
local MITRE + runbook corpus, then ask the LLM to answer using only that
context - this is what makes it RAG rather than an ungrounded LLM call.
"""

from .. import llm_client
from .retriever import load_corpus, retrieve

_SYSTEM = """You explain ATT&CK techniques and response guidance to a SOC \
analyst using an EDR system. Answer using ONLY the provided context - if \
the context doesn't cover something the analyst asked, say so rather than \
guessing. Be concise and practical."""


def _context_block(docs: list[dict]) -> str:
    return "\n\n---\n\n".join(d["text"] for d in docs)


def explain(query: str, k: int = 3) -> dict:
    """query can be a technique ID ("T1059") or a free-text question
    ("how does this EDR catch reverse shells"). Returns the answer plus
    which corpus docs grounded it, so the panel can cite sources."""
    docs = load_corpus()

    normalized = query.strip().upper()
    direct_matches = [d for d in docs if normalized in d["doc_id"].split("_")]
    context_docs = direct_matches or retrieve(query, k=k, docs=docs)

    if not context_docs:
        return {
            "answer": (
                "I don't have grounding material on that in the local corpus "
                "(covers the 12 scoped techniques and the response runbook)."
            ),
            "sources": [],
        }

    prompt = f"Analyst question: {query}\n\nContext:\n{_context_block(context_docs)}"
    answer = llm_client.complete(_SYSTEM, prompt)
    return {"answer": answer, "sources": [d["doc_id"] for d in context_docs]}
