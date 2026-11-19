"""
Adapter for Local / On-Premise LLM execution using Ollama (free, private, local).
Supported models: llama3:8b, mistral:7b, phi3, etc.
"""

from typing import Any, Dict, Optional
import os
import json
import urllib.request
import urllib.error
from ..interface import LLMProvider, LLMGatewayError, LLMTimeoutError


class OllamaLocalProvider(LLMProvider):
    """
    Client for local Ollama HTTP REST API (`/api/generate`).
    Guarantees that inference runs 100% on-premise without external network egress.
    """

    def __init__(
        self,
        model_name: str = "llama3:8b",
        host: str = "http://localhost:11434",
        config: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(model_name=model_name, config=config)
        clean_host = (host or "http://localhost:11434").strip()
        if not clean_host.startswith(("http://", "https://")):
            clean_host = f"http://{clean_host}"
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(clean_host)
        netloc = parsed.netloc
        if netloc in ("0.0.0.0", "localhost", "127.0.0.1"):
            netloc = "localhost:11434"
        elif netloc.startswith("0.0.0.0:"):
            netloc = "localhost:" + netloc.split(":")[1]
        self.host = urlunparse((parsed.scheme or "http", netloc, "", "", "", "")).rstrip("/")

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 2000,
        format: Optional[str] = None,
        **kwargs,
    ) -> str:
        url = f"{self.host}/api/generate"
        num_ctx = int(
            self.config.get("num_ctx")
            or os.environ.get("OLLAMA_NUM_CTX")
            or os.environ.get("OLLAMA_CONTEXT_LENGTH")
            or 16384
        )
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
                "num_ctx": num_ctx,
            }
        }

        if system_prompt:
            payload["system"] = system_prompt

        if format == "json" or kwargs.get("format") == "json":
            payload["format"] = "json"

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        timeout = self.config.get("timeout", 180)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result.get("response", "")
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            if e.code == 404:
                raise LLMGatewayError(f"Ollama model '{self.model_name}' not found. Run `ollama pull {self.model_name}` first. Details: {err_body}")
            raise LLMGatewayError(f"Ollama server returned HTTP {e.code}: {err_body}")
        except urllib.error.URLError as e:
            if "timeout" in str(e.reason).lower():
                raise LLMTimeoutError(f"Ollama request timed out after {timeout}s.")
            raise LLMGatewayError(
                f"Failed to connect to local Ollama instance at {self.host}. "
                f"Ensure Ollama is running (`ollama serve`). Details: {e.reason}"
            )
        except TimeoutError:
            raise LLMTimeoutError(f"Ollama request timed out after {timeout}s.")
        except Exception as e:
            raise LLMGatewayError(f"Ollama execution error: {e}")
