"""Prompt templates and system guidelines for LLM workflows."""
from .summarization_prompts import SUMMARIZATION_SYSTEM_PROMPT, build_summarization_prompt
from .extraction_prompts import EXTRACTION_SYSTEM_PROMPT, build_extraction_prompt
from .investigation_prompts import INVESTIGATION_SYSTEM_PROMPT, build_investigation_prompt

__all__ = [
    "SUMMARIZATION_SYSTEM_PROMPT",
    "build_summarization_prompt",
    "EXTRACTION_SYSTEM_PROMPT",
    "build_extraction_prompt",
    "INVESTIGATION_SYSTEM_PROMPT",
    "build_investigation_prompt",
]
