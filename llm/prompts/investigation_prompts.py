"""
Prompt templates for Workflow 3: Evidence-Grounded Threat Investigation (RAG).
Synthesizes retrieved historical evidence from Team 2 into grounded investigator findings.
"""

from typing import List, Dict, Any

INVESTIGATION_SYSTEM_PROMPT = """You are a cybersecurity incident investigator at UNICC.
You are assisting a human analyst who is investigating a newly observed suspicious indicator or threat event.

CRITICAL GROUNDING & ANTI-HALLUCINATION RULES:
1. Every claim, correlation, or attribution you make MUST be directly anchored in the provided Historical Evidence.
2. For each correlation, cite the specific Document ID and include the key excerpt that proves the link.
3. Categorize the historical match strictly into one of:
   - 'Exact': Identical IOC or vulnerability observed with matching malicious activity.
   - 'Strong': Highly overlapping campaign indicators, infrastructure, or attack patterns.
   - 'Partial': Shared malware or technique, but distinct infrastructure or unknown affiliation.
   - 'Weak': Minor incidental overlap (e.g. generic tool or protocol).
   - 'Unsupported': No credible historical evidence found connecting the observation.
4. Always include a disclaimer that this is an AI-assisted analysis requiring human investigator review.
5. Return strictly valid JSON conforming to the schema.
"""


def build_investigation_prompt(
    observation: str,
    retrieved_evidence: List[Dict[str, Any]],
) -> str:
    """
    Builds the prompt combining newly observed threat details with retrieved historical evidence.
    """
    evidence_text = ""
    for idx, doc in enumerate(retrieved_evidence, 1):
        doc_id = doc.get("document_id", f"DOC-{idx}")
        score = doc.get("relevance_score", "N/A")
        content = doc.get("content", "").strip()
        evidence_text += (
            f"--- [EVIDENCE #{idx}] Document ID: {doc_id} (Relevance: {score}) ---\n"
            f"{content}\n\n"
        )

    return (
        f"NEWLY OBSERVED THREAT / QUERY:\n"
        f"{observation.strip()}\n\n"
        f"RETRIEVED HISTORICAL EVIDENCE FROM KNOWLEDGE BASE (Team 2 Retrieval):\n"
        f"{evidence_text}\n"
        f"TASK:\n"
        f"Synthesize the historical evidence and determine whether this threat has been documented previously. "
        f"Provide your assessment in a JSON object with keys:\n"
        f"- query_observation: string\n"
        f"- match_status: 'Exact' | 'Strong' | 'Partial' | 'Weak' | 'Unsupported'\n"
        f"- assessment_narrative: detailed grounded synthesis\n"
        f"- potential_threat_actors: list of strings\n"
        f"- associated_malware: list of strings\n"
        f"- associated_cves: list of strings\n"
        f"- confidence_level: 'High' | 'Medium' | 'Low'\n"
        f"- supporting_citations: list of objects {{document_id, relevance_score, key_excerpt, observed_overlap}}\n"
        f"- investigator_notes: string reminding analyst of human verification\n"
    )
