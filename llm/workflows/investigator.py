"""
Workflow 3: Evidence-Grounded Threat Investigation (RAG).
Combines newly observed threats with retrieved historical evidence (Team 2)
to produce a grounded, citation-backed investigation report.
Natively ingests Team 2's MatchResponse, TopMatchSchema, or dict formats directly.
Can also directly query Team 2's existing HTTP POST endpoint automatically.
"""

from typing import List, Dict, Any, Union, Optional
import os
import json
import urllib.request
import urllib.error
from ..gateway.interface import LLMProvider
from ..schemas.investigation import InvestigationResult
from ..prompts.investigation_prompts import INVESTIGATION_SYSTEM_PROMPT, build_investigation_prompt


def fetch_team2_evidence(
    query: str,
    api_url: str = "http://localhost:8000",
    top_k: int = 5,
) -> Any:
    """
    Sends an HTTP POST to Team 2's EXISTING API endpoint (/api/v1/threats/match or /match).
    Team 2's code is not modified; we simply call their live API over HTTP.
    """
    base = api_url.rstrip("/")
    payload = json.dumps({"query": query, "top_k": top_k, "alpha": 0.5}).encode("utf-8")

    # Try preferred endpoint first
    endpoints = [
        f"{base}/api/v1/threats/match",
        f"{base}/match",
        f"{base}/query",
    ]

    last_err = None
    for ep in endpoints:
        req = urllib.request.Request(
            ep,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            last_err = e
            continue

    raise ConnectionError(
        f"Could not reach Team 2 API at {api_url}. "
        f"Ensure Team 2's server is running (`uvicorn threat_retrieval_engine.api.main:app`). Details: {last_err}"
    )


def normalize_team2_evidence(evidence_input: Any) -> List[Dict[str, Any]]:
    """
    Natively normalizes evidence from Team 2's retrieval engine without requiring an external adapter.
    Handles:
      - Team 2 MatchResponse object (extracts top_matches)
      - List of Team 2 TopMatchSchema objects
      - List of dictionaries from Team 2's JSON API (/match or /query)
      - Standard list of {"document_id", "relevance_score", "content"}
    """
    if evidence_input is None:
        return []

    # If evidence_input is Team 2's MatchResponse
    if hasattr(evidence_input, "top_matches"):
        raw_items = evidence_input.top_matches
    elif isinstance(evidence_input, dict) and "top_matches" in evidence_input:
        raw_items = evidence_input["top_matches"]
    elif isinstance(evidence_input, (list, tuple)):
        raw_items = evidence_input
    else:
        raw_items = [evidence_input]

    normalized: List[Dict[str, Any]] = []
    for item in raw_items:
        if isinstance(item, dict):
            citations = item.get("citations", [])
            chunk_id = item.get("chunk_id") or item.get("document_id") or "EVIDENCE"
            score = item.get("composite_score") or item.get("relevance_score") or 0.0

            if citations and isinstance(citations, list) and len(citations) > 0:
                first_cit = citations[0]
                if isinstance(first_cit, dict):
                    doc_id = first_cit.get("doc_id") or first_cit.get("document_id") or chunk_id
                    content = first_cit.get("text_snippet") or first_cit.get("content") or item.get("text", "")
                    source = first_cit.get("source_org", "Team 2 Knowledge Base")
                else:
                    doc_id = getattr(first_cit, "doc_id", chunk_id)
                    content = getattr(first_cit, "text_snippet", item.get("text", ""))
                    source = getattr(first_cit, "source_org", "Team 2 Knowledge Base")
            else:
                doc_id = item.get("document_id") or chunk_id
                content = item.get("content") or item.get("text") or ""
                source = item.get("source", "Team 2 Knowledge Base")

        else:
            # Pydantic or dataclass object from Team 2 (e.g. TopMatchSchema)
            chunk_id = getattr(item, "chunk_id", "EVIDENCE")
            score = getattr(item, "composite_score", getattr(item, "relevance_score", 0.0))
            citations = getattr(item, "citations", [])
            if citations and len(citations) > 0:
                first_cit = citations[0]
                doc_id = getattr(first_cit, "doc_id", chunk_id)
                content = getattr(first_cit, "text_snippet", getattr(item, "text", ""))
                source = getattr(first_cit, "source_org", "Team 2 Knowledge Base")
            else:
                doc_id = getattr(item, "document_id", chunk_id)
                content = getattr(item, "content", getattr(item, "text", ""))
                source = getattr(item, "source", "Team 2 Knowledge Base")

        normalized.append({
            "document_id": str(doc_id),
            "relevance_score": float(score),
            "content": str(content).strip(),
            "source": str(source),
        })

    return normalized


class ThreatInvestigator:
    """Encapsulates RAG-based threat investigation and evidence grounding."""

    def __init__(self, provider: LLMProvider):
        self.provider = provider

    def investigate(
        self,
        observation: str,
        retrieved_evidence: Any = None,
        team2_api_url: Optional[str] = None,
    ) -> InvestigationResult:
        """
        Synthesizes historical evidence to assess a newly observed threat.
        If retrieved_evidence is None, automatically POSTs the query to Team 2's API!
        Natively accepts Team 2's direct MatchResponse or TopMatchSchema output.
        Enforces source citations and anti-hallucination guardrails.
        """
        if not observation or not observation.strip():
            raise ValueError("Observation cannot be empty.")

        # If evidence was not pre-fetched, query Team 2's existing API directly
        if retrieved_evidence is None:
            url = team2_api_url or os.getenv("TEAM2_API_URL", "http://localhost:8000")
            retrieved_evidence = fetch_team2_evidence(query=observation, api_url=url)

        # Natively normalize Team 2 format into standard evidence list
        clean_evidence = normalize_team2_evidence(retrieved_evidence)

        prompt = build_investigation_prompt(observation, clean_evidence)

        result: InvestigationResult = self.provider.generate_structured(
            prompt=prompt,
            schema_cls=InvestigationResult,
            system_prompt=INVESTIGATION_SYSTEM_PROMPT,
        )

        # Post-validation check: Ensure all citations reference actual provided evidence
        provided_doc_ids = {doc.get("document_id") for doc in clean_evidence if doc.get("document_id")}
        for citation in result.supporting_citations:
            if provided_doc_ids and citation.document_id not in provided_doc_ids:
                citation.key_excerpt = f"[Unverified Reference] {citation.key_excerpt}"

        return result
