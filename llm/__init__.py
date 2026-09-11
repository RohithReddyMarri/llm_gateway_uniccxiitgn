"""
UNICC x IITGN AI & Cybersecurity Capstone Project
Team 3: LLM Intelligence & Evaluation Layer

High-level SDK functions designed for seamless 1-line integration by Team 4 (UI/Backend):
- summarize_report(report_text, backend="mock"|"local"|"api") -> dict
- extract_entities(text, backend="mock"|"local"|"api") -> dict
- investigate_threat(observation, retrieved_evidence, backend="mock"|"local"|"api") -> dict
"""

from typing import Dict, Any, List, Optional
from .gateway.factory import get_llm_provider
from .workflows.summarizer import ReportSummarizer
from .workflows.extractor import CyberEntityExtractor
from .workflows.investigator import ThreatInvestigator

__version__ = "0.2.0"


def summarize_report(
    report_text: str,
    backend: Optional[str] = None,
    model_name: Optional[str] = None,
    focus_areas: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Summarizes a cybersecurity report and returns a clean dictionary/JSON for Team 4.
    """
    provider = get_llm_provider(backend=backend, model_name=model_name, **kwargs)
    summarizer = ReportSummarizer(provider)
    result = summarizer.summarize(report_text, focus_areas=focus_areas)
    return result.to_dict() if hasattr(result, "to_dict") else result


def extract_entities(
    text: str,
    backend: Optional[str] = None,
    model_name: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Extracts structured CVEs, IOCs, Malware, and Threat Actors into a clean dictionary/JSON for Team 4.
    """
    provider = get_llm_provider(backend=backend, model_name=model_name, **kwargs)
    extractor = CyberEntityExtractor(provider)
    result = extractor.extract(text)
    return result.to_dict() if hasattr(result, "to_dict") else result


def investigate_threat(
    observation: str,
    retrieved_evidence: List[Dict[str, Any]],
    backend: Optional[str] = None,
    model_name: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Evidence-grounded threat investigation (RAG).
    Takes a new threat query and Team 2's historical evidence,
    and returns a citation-backed assessment dictionary/JSON for Team 4.
    """
    provider = get_llm_provider(backend=backend, model_name=model_name, **kwargs)
    investigator = ThreatInvestigator(provider)
    result = investigator.investigate(observation, retrieved_evidence)
    return result.to_dict() if hasattr(result, "to_dict") else result


__all__ = [
    "summarize_report",
    "extract_entities",
    "investigate_threat",
    "get_llm_provider",
    "ReportSummarizer",
    "CyberEntityExtractor",
    "ThreatInvestigator",
]
