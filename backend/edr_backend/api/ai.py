from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..ai import nl2query
from ..ai.llm_client import LLMNotConfigured
from ..ai.rag.explain import explain
from ..ai.summarizer import summarize_incident
from ..core.db import get_db
from ..core.security import require_token
from ..correlation.incident_view import build_incident_view

router = APIRouter(dependencies=[Depends(require_token)])


class SummarizeResponse(BaseModel):
    incident_id: int
    summary: str


class NL2QueryRequest(BaseModel):
    query: str


class ExplainRequest(BaseModel):
    query: str


@router.post("/ai/summarize/{incident_id}", response_model=SummarizeResponse)
def summarize(incident_id: int, db: Session = Depends(get_db)) -> SummarizeResponse:
    view = build_incident_view(db, incident_id)
    if view is None:
        raise HTTPException(status_code=404, detail="incident not found")
    try:
        summary = summarize_incident(
            view["incident"], view["alerts"], view["timeline"], view["process_tree"]
        )
    except LLMNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return SummarizeResponse(incident_id=incident_id, summary=summary)


@router.post("/ai/nl2query")
def run_nl2query(req: NL2QueryRequest) -> dict:
    try:
        return nl2query.translate(req.query)
    except LLMNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/ai/explain")
def run_explain(req: ExplainRequest) -> dict:
    try:
        return explain(req.query)
    except LLMNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
