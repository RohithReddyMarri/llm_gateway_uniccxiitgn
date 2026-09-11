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

    def __init__(self, provider: LLMProvider):
        self.provider = provider

    def summarize(self, report_text: str, focus_areas: Optional[str] = None) -> ThreatReportSummary:
        """
        Summarizes an input report into a validated ThreatReportSummary.
        """
        if not report_text or not report_text.strip():
            raise ValueError("Input report text cannot be empty.")

        prompt = build_summarization_prompt(report_text, focus_areas=focus_areas)
        
        summary = self.provider.generate_structured(
            prompt=prompt,
            schema_cls=ThreatReportSummary,
            system_prompt=SUMMARIZATION_SYSTEM_PROMPT,
        )
        return summary
