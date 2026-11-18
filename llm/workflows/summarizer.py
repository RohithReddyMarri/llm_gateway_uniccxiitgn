"""
Workflow 1: Report Summarization.
Processes long-form cybersecurity reports and generates concise, structured findings.
"""

from typing import Optional
from ..gateway.interface import LLMProvider
from ..schemas.report_summary import ThreatReportSummary
from ..prompts.summarization_prompts import SUMMARIZATION_SYSTEM_PROMPT, build_summarization_prompt


class ReportSummarizer:
    """Encapsulates report summarization logic and validation."""

    MAX_SAFE_CHARS = 12000  # Safe context budget for local LLM inference (~3k tokens)

    def __init__(self, provider: LLMProvider):
        self.provider = provider

    def summarize(self, report_text: str, focus_areas: Optional[str] = None) -> ThreatReportSummary:
        """
        Summarizes an input report into a validated ThreatReportSummary.
        Applies smart context windowing to prevent local model OOM or silent context truncation.
        """
        if not report_text or not report_text.strip():
            raise ValueError("Input report text cannot be empty.")

        clean_text = report_text.strip()
        if len(clean_text) > self.MAX_SAFE_CHARS:
            # Head-Tail context preservation: Keeps critical threat intro & trailing mitigations
            clean_text = (
                f"{clean_text[:8000]}\n\n"
                f"[... Notice: Report length ({len(clean_text):,} chars) exceeded local context budget. "
                f"Preserving threat executive overview and concluding remediation sections ...]\n\n"
                f"{clean_text[-3500:]}"
            )

        prompt = build_summarization_prompt(clean_text, focus_areas=focus_areas)
        
        summary = self.provider.generate_structured(
            prompt=prompt,
            schema_cls=ThreatReportSummary,
            system_prompt=SUMMARIZATION_SYSTEM_PROMPT,
        )
        return summary
