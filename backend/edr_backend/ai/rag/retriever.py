"""Retrieval over the local MITRE technique + runbook corpus.

Lab scale (a dozen short documents), so a keyword-overlap score is enough -
no embedding model or vector store needed. Swap for real embeddings if the
corpus grows past what a human still wants to read end to end.
"""

import re
from pathlib import Path

_CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
_WORD_RE = re.compile(r"[a-z0-9]+")

_STOPWORDS = {
    "the", "a", "an", "is", "are", "was", "were", "of", "to", "in", "on",
    "for", "and", "or", "this", "that", "it", "its", "by", "as", "with",
    "be", "at", "so", "if", "not",
}


def _tokenize(text: str) -> set[str]:
    return {w for w in _WORD_RE.findall(text.lower()) if w not in _STOPWORDS}


def load_corpus() -> list[dict]:
    """Every doc in corpus/, as {doc_id, title, text}. doc_id is the
    filename stem (matches technique IDs like 'T1059', or 'runbook')."""
    docs = []
    for path in sorted(_CORPUS_DIR.glob("*.md")):
        text = path.read_text()
        title = text.splitlines()[0].lstrip("# ").strip() if text else path.stem
        docs.append({"doc_id": path.stem, "title": title, "text": text})
    return docs


def retrieve(query: str, k: int = 3, docs: list[dict] | None = None) -> list[dict]:
    """Top-k docs by token overlap with the query. Ties broken by doc_id
    for deterministic output."""
    docs = docs if docs is not None else load_corpus()
    query_tokens = _tokenize(query)
    if not query_tokens:
        return []

    scored = []
    for doc in docs:
        overlap = len(query_tokens & _tokenize(doc["text"]))
        if overlap > 0:
            scored.append((overlap, doc))

    scored.sort(key=lambda pair: (-pair[0], pair[1]["doc_id"]))
    return [doc for _, doc in scored[:k]]
