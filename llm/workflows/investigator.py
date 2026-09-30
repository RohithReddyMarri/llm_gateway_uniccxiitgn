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
    # Gracefully trim endpoint suffix if caller included it
    for suffix in ["/api/v1/threats/match", "/match", "/query"]:
        if base.endswith(suffix):
            base = base[:-len(suffix)].rstrip("/")
            break

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
    Preserves STIX relationships, confidence tier, attribution, and multi-factor similarity.
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
            stix = item.get("stix_relationships", [])
            tier = item.get("confidence_tier")
            attr = item.get("attribution", {})
            breakdown = item.get("evidence_breakdown", {})

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
            stix = getattr(item, "stix_relationships", [])
            tier = getattr(item, "confidence_tier", None)
            attr = getattr(item, "attribution", {})
            breakdown = getattr(item, "evidence_breakdown", {})

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
            "confidence_tier": tier,
            "stix_relationships": stix,
            "attribution": attr,
            "evidence_breakdown": breakdown,
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

        # Post-validation check: Harmonize and resolve citations to real document IDs
        # Prevents brittle string-equality failures when LLM cites 'EVIDENCE #1' or base CVE
        doc_id_map: Dict[str, str] = {}
        for idx, doc in enumerate(clean_evidence, 1):
            real_id = doc.get("document_id", "")
            if real_id:
                doc_id_map[real_id.lower()] = real_id
                doc_id_map[f"evidence #{idx}".lower()] = real_id
                doc_id_map[f"evidence {idx}".lower()] = real_id
                doc_id_map[f"doc-{idx}".lower()] = real_id
                doc_id_map[f"doc #{idx}".lower()] = real_id
                doc_id_map[f"doc {idx}".lower()] = real_id
                # Map without underscores/suffixes (e.g. CVE-2017-0144_EPSS -> CVE-2017-0144)
                base_cve = real_id.split("_")[0]
                doc_id_map[base_cve.lower()] = real_id

        for citation in result.supporting_citations:
            raw_cid = (citation.document_id or "").strip().lower()
            if raw_cid in doc_id_map:
                # Automatically resolve to the authoritative document ID
                citation.document_id = doc_id_map[raw_cid]
            elif any(raw_cid in valid_id or valid_id in raw_cid for valid_id in doc_id_map):
                matching_real_id = next(doc_id_map[k] for k in doc_id_map if raw_cid in k or k in raw_cid)
                citation.document_id = matching_real_id
            else:
                if doc_id_map:
                    citation.key_excerpt = f"[Unverified Reference] {citation.key_excerpt}"

        return result
