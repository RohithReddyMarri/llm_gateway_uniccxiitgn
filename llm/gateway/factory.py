"""
Factory method to instantiate the appropriate LLM provider.
Provides zero-downtime, model-agnostic switching without touching downstream application logic.
"""

from typing import Optional, Dict, Any
import os
from .interface import LLMProvider
from .mock_provider import MockLLMProvider
from .local.ollama_provider import OllamaLocalProvider
from .api.api_provider import APILLMProvider


def get_llm_provider(
    backend: Optional[str] = None,
    model_name: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None,
    **kwargs
) -> LLMProvider:
    """
    Factory to retrieve an initialized LLMProvider instance.

    Args:
        backend: "mock", "local", or "api". Defaults to LLM_BACKEND env var or "mock".
        model_name: Optional model identifier (e.g., 'llama3:8b', 'gpt-4o-mini').
        config: Optional configuration dictionary.
    """
    selected_backend = (backend or os.getenv("LLM_BACKEND", "mock")).strip().lower()

    if selected_backend == "mock":
        return MockLLMProvider(
            model_name=model_name or "mock-cyber-v1",
            config=config,
        )

    elif selected_backend in ("local", "onprem", "ollama"):
        host = kwargs.get("host") or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        return OllamaLocalProvider(
            model_name=model_name or os.getenv("LOCAL_MODEL_NAME", "llama3:8b"),
            host=host,
            config=config,
        )

    elif selected_backend in ("api", "cloud", "openai"):
        base_url = kwargs.get("base_url") or os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
        return APILLMProvider(
            model_name=model_name or os.getenv("API_MODEL_NAME", "gpt-4o-mini"),
            api_key=kwargs.get("api_key"),
            base_url=base_url,
            config=config,
        )

    else:
        raise ValueError(
            f"Unknown LLM backend: '{selected_backend}'. "
            f"Supported backends are: 'mock', 'local', 'api'."
        )
