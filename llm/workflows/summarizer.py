"""
Workflow 1: Cybersecurity Report Summarization.
Synthesizes extensive technical threat intelligence into executive and operational briefs.
"""

from typing import Optional
from ..gateway.interface import LLMProvider
from ..schemas.report_summary import ThreatReportSummary
from ..prompts.summarization_prompts import SUMMARIZATION_SYSTEM_PROMPT, build_summarization_prompt


class ReportSummarizer:
    """Encapsulates report summarization and validation."""

    MAX_SAFE_CHARS = 12000

    def __init__(self, provider: LLMProvider):
        self.provider = provider

    def summarize(self, report_text: str, focus_areas: Optional[str] = None) -> ThreatReportSummary:
        """
        Summarizes an input report into a validated ThreatReportSummary.
        Applies boundary-aware context windowing to prevent local model OOM or truncation.
        """
        if not report_text or not report_text.strip():
            raise ValueError("Input report text cannot be empty.")

        clean_text = report_text.strip()
        if len(clean_text) > self.MAX_SAFE_CHARS:
            # Boundary-aware slicing: find natural paragraph or sentence breaks
            head_break = clean_text.rfind("\n\n", 0, 8000)
            if head_break == -1 or head_break < 4000:
                head_break = clean_text.rfind(". ", 0, 8000)
            head = clean_text[:head_break + 1] if head_break != -1 else clean_text[:8000]

            tail_start = clean_text.find("\n\n", len(clean_text) - 3500)
            if tail_start == -1 or tail_start > len(clean_text) - 1500:
                tail_start = clean_text.find(". ", len(clean_text) - 3500)
            tail = clean_text[tail_start + 1:] if tail_start != -1 else clean_text[-3500:]

            clean_text = (
                f"{head.strip()}\n\n"
                f"[... Notice: Report length ({len(report_text):,} chars) exceeded context budget. "
                f"Preserving executive overview and concluding remediation sections ...]\n\n"
                f"{tail.strip()}"
            )

        prompt = build_summarization_prompt(clean_text, focus_areas=focus_areas)
        
        summary = self.provider.generate_structured(
            prompt=prompt,
            schema_cls=ThreatReportSummary,
            system_prompt=SUMMARIZATION_SYSTEM_PROMPT,
        )
        return summary
