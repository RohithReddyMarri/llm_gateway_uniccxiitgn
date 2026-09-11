"""
Workflow 3: Evidence-Grounded Threat Investigation (RAG).
Combines newly observed threats with retrieved historical evidence (Team 2)
to produce a grounded, citation-backed investigation report.
"""

from typing import List, Dict, Any
from ..gateway.interface import LLMProvider
from ..schemas.investigation import InvestigationResult
from ..prompts.investigation_prompts import INVESTIGATION_SYSTEM_PROMPT, build_investigation_prompt


class ThreatInvestigator:
    """Encapsulates RAG-based threat investigation and evidence grounding."""

    def __init__(self, provider: LLMProvider):
        self.provider = provider

    def investigate(
        self,
        observation: str,
        retrieved_evidence: List[Dict[str, Any]],
    ) -> InvestigationResult:
        """
        Synthesizes historical evidence to assess a newly observed threat.
        Enforces source citations and anti-hallucination guardrails.
        """
        if not observation or not observation.strip():
            raise ValueError("Observation cannot be empty.")

        prompt = build_investigation_prompt(observation, retrieved_evidence)

        result: InvestigationResult = self.provider.generate_structured(
            prompt=prompt,
            schema_cls=InvestigationResult,
            system_prompt=INVESTIGATION_SYSTEM_PROMPT,
        )

        # Post-validation check: Ensure all citations reference actual provided evidence
        provided_doc_ids = {doc.get("document_id") for doc in retrieved_evidence if doc.get("document_id")}
        for citation in result.supporting_citations:
            if provided_doc_ids and citation.document_id not in provided_doc_ids:
                citation.key_excerpt = f"[Unverified Reference] {citation.key_excerpt}"

        return result
