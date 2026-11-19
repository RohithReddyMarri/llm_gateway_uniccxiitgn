"""
Workflow 3: Evidence-Grounded Threat Investigation (RAG).
Synthesizes retrieved historical records into a calibrated threat triage report.
"""

from typing import Any, Dict, List, Optional, Union
import json
import urllib.request
import urllib.error
from ..gateway.interface import LLMProvider
from ..schemas.investigation import InvestigationResult
from ..prompts.investigation_prompts import INVESTIGATION_SYSTEM_PROMPT, build_investigation_prompt


def normalize_team2_evidence(raw_evidence: Any) -> List[Dict[str, Any]]:
    """
    Translates raw retrieval engine responses into a clean, normalized evidence schema.
    Handles top_matches, supporting_evidence_chunks, dictionaries, and Pydantic models.
    Preserves all supporting document citations instead of arbitrarily truncating to citations[0].
    """
    if not raw_evidence:
        return []

    # If already a list of dicts with document_id and content, return directly
    if isinstance(raw_evidence, list) and all(isinstance(x, dict) and "document_id" in x for x in raw_evidence):
        return raw_evidence

    # If wrapped in a dict with top_matches (standard /threats/match payload)
    if isinstance(raw_evidence, dict) and "top_matches" in raw_evidence:
        raw_evidence = raw_evidence["top_matches"]

    normalized = []
    for item in raw_evidence:
        if isinstance(item, dict):
            chunk_id = item.get("chunk_id") or item.get("id") or "EVIDENCE"
            score = (
                item.get("composite_score")
                if item.get("composite_score") is not None
                else (item.get("relevance_score") if item.get("relevance_score") is not None else 0.0)
            )
            citations = item.get("citations", [])
            stix = item.get("stix_relationships", [])
            tier = item.get("confidence_tier")
            attr = item.get("attribution", {})
            breakdown = item.get("evidence_breakdown", {})

            if citations and isinstance(citations, list) and len(citations) > 0:
                for cit in citations:
                    if isinstance(cit, dict):
                        doc_id = cit.get("doc_id") or cit.get("document_id") or chunk_id
                        content = cit.get("text_snippet") or cit.get("content") or item.get("text", "")
                        source = cit.get("source_org", "Knowledge Base")
                    else:
                        doc_id = getattr(cit, "doc_id", chunk_id)
                        content = getattr(cit, "text_snippet", item.get("text", ""))
                        source = getattr(cit, "source_org", "Knowledge Base")
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
            else:
                doc_id = item.get("document_id") or chunk_id
                content = item.get("content") or item.get("text") or ""
                source = item.get("source", "Knowledge Base")
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

        else:
            chunk_id = getattr(item, "chunk_id", "EVIDENCE")
            score = (
                getattr(item, "composite_score")
                if getattr(item, "composite_score", None) is not None
                else (getattr(item, "relevance_score", 0.0) if getattr(item, "relevance_score", None) is not None else 0.0)
            )
            citations = getattr(item, "citations", [])
            stix = getattr(item, "stix_relationships", [])
            tier = getattr(item, "confidence_tier", None)
            attr = getattr(item, "attribution", {})
            breakdown = getattr(item, "evidence_breakdown", {})

            if citations and len(citations) > 0:
                for cit in citations:
                    doc_id = getattr(cit, "doc_id", chunk_id)
                    content = getattr(cit, "text_snippet", getattr(item, "text", ""))
                    source = getattr(cit, "source_org", "Knowledge Base")
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
            else:
                doc_id = getattr(item, "document_id", chunk_id)
                content = getattr(item, "content", getattr(item, "text", ""))
                source = getattr(item, "source", "Knowledge Base")
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

    def fetch_retrieval_evidence(
        self,
        observation: str,
        api_url: str = "http://localhost:8000",
        top_k: int = 5,
        allowed_sources: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Directly queries the Threat Retrieval & Matching REST API.
        """
        endpoint = f"{api_url.rstrip('/')}/api/v1/threats/match"
        payload = {
            "query": observation,
            "top_k": top_k,
            "alpha": 0.5,
            "include_pocs": False,
        }
        if allowed_sources:
            payload["allowed_sources"] = allowed_sources

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return normalize_team2_evidence(result)
        except Exception as e:
            print(f"WARN: Could not fetch evidence from retrieval API: {e}. Proceeding offline.")
            return []

    def investigate(
        self,
        observation: str,
        retrieved_evidence: Optional[Any] = None,
        team2_api_url: Optional[str] = None,
        allowed_sources: Optional[List[str]] = None,
    ) -> InvestigationResult:
        """
        Executes an evidence-grounded threat investigation.
        """
        if not observation or not observation.strip():
            raise ValueError("Observation text cannot be empty.")

        # If live retrieval URL is provided, query it automatically
        if team2_api_url and not retrieved_evidence:
            clean_evidence = self.fetch_retrieval_evidence(
                observation,
                api_url=team2_api_url,
                allowed_sources=allowed_sources
            )
        else:
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
                # Only set base_cve if not already mapped to avoid collision overwrites
                base_cve = real_id.split("_")[0].lower()
                if base_cve.startswith("cve-") and base_cve not in doc_id_map:
                    doc_id_map[base_cve] = real_id

        for citation in result.supporting_citations:
            raw_cid = (citation.document_id or "").strip().lower()
            if raw_cid in doc_id_map:
                citation.document_id = doc_id_map[raw_cid]
            else:
                citation.key_excerpt = f"[Unverified Citation: {citation.document_id}] {citation.key_excerpt}"

        return result
