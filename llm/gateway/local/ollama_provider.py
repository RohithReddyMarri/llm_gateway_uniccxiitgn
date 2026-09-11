"""
Adapter for Local On-Premise LLMs (Ollama / vLLM HTTP endpoints).
Complies with UNICC requirements for private, air-gapped internal operations.
"""

from typing import Any, Dict, Optional
import json
import urllib.request
import urllib.error
from ..interface import LLMProvider


class OllamaLocalProvider(LLMProvider):
    """
    Connects to a locally hosted LLM via Ollama (e.g. llama3:8b, mistral:7b).
    Does not transmit any data to external public networks.
    """

    def __init__(
        self,
        model_name: str = "llama3:8b",
        host: str = "http://localhost:11434",
        config: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(model_name=model_name, config=config)
        self.host = host.rstrip("/")

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 2000,
    ) -> str:
        url = f"{self.host}/api/generate"
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "system": system_prompt or "You are a cybersecurity intelligence analyst.",
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            }
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result.get("response", "")
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Failed to connect to local Ollama instance at {self.host}. "
                f"Ensure Ollama is running (`ollama serve`). Details: {e}"
            )
