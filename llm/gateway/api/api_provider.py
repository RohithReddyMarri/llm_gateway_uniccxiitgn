"""
Adapter for External / Cloud API-based LLMs (OpenAI, Gemini via OpenAI-compat, Groq, etc.).
Allows testing larger models during development and evaluation benchmarking.
"""

from typing import Any, Dict, Optional
import os
import json
import urllib.request
import urllib.error
from ..interface import LLMProvider


class APILLMProvider(LLMProvider):
    """
    Standard HTTP client for OpenAI-compatible chat completion endpoints.
    Compatible with:
    - OpenAI (gpt-4o, gpt-4o-mini)
    - Google Gemini (via OpenAI compatibility endpoint)
    - Groq / Together AI / Mistral AI
    """

    def __init__(
        self,
        model_name: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        base_url: str = "https://api.openai.com/v1",
        config: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(model_name=model_name, config=config)
        self.api_key = api_key or os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.base_url = base_url.rstrip("/")

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 2000,
    ) -> str:
        if not self.api_key:
            raise ValueError(
                "API key not found. Please set LLM_API_KEY or OPENAI_API_KEY in environment, "
                "or pass api_key to APILLMProvider."
            )

        url = f"{self.base_url}/chat/completions"
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            raise RuntimeError(f"API request failed [{e.code}]: {err_body}")
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to connect to API endpoint at {self.base_url}: {e}")
