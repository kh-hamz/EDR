"""Thin wrapper over the Claude API, the one place the rest of the ai/
package talks to Anthropic. Kept provider-agnostic in spirit (a single
`complete()` entry point) so summarizer/nl2query/rag don't touch the SDK
directly.
"""

import json
import os

import anthropic

from ..core.config import settings

MODEL = settings.llm_model


class LLMNotConfigured(RuntimeError):
    pass


def _client() -> anthropic.Anthropic:
    if settings.llm_api_key:
        return anthropic.Anthropic(api_key=settings.llm_api_key)
    if os.environ.get("ANTHROPIC_API_KEY"):
        return anthropic.Anthropic()
    raise LLMNotConfigured(
        "no LLM API key configured: set LLM_API_KEY in .env "
        "(or ANTHROPIC_API_KEY in the environment)"
    )


def complete(system: str, user: str, max_tokens: int = 2048) -> str:
    """One-shot completion: system + a single user turn, adaptive thinking,
    return the first text block. All ai/ callers go through this."""
    response = _client().messages.create(
        model=MODEL,
        max_tokens=max_tokens,
        thinking={"type": "adaptive"},
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    text = next((b.text for b in response.content if b.type == "text"), "")
    if not text:
        raise RuntimeError(f"LLM returned no text (stop_reason={response.stop_reason})")
    return text


def complete_structured(system: str, user: str, schema: dict, max_tokens: int = 1024) -> dict:
    """Like complete(), but constrains the response to `schema` (JSON Schema)
    via structured outputs, so callers get a parsed dict instead of parsing
    free text themselves."""
    response = _client().messages.create(
        model=MODEL,
        max_tokens=max_tokens,
        thinking={"type": "adaptive"},
        system=system,
        output_config={"format": {"type": "json_schema", "schema": schema}},
        messages=[{"role": "user", "content": user}],
    )
    text = next((b.text for b in response.content if b.type == "text"), "")
    if not text:
        raise RuntimeError(f"LLM returned no text (stop_reason={response.stop_reason})")
    return json.loads(text)
