"""
Model-Agnostic LLM Gateway for UNICC Cybersecurity Intelligence.
Provides unified interfaces for local/on-premise and external/API-based LLMs.
"""

from .interface import LLMProvider
from .factory import get_llm_provider

__all__ = ["LLMProvider", "get_llm_provider"]
