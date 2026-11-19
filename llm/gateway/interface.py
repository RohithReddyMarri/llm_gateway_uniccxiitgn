"""
Abstract Base Class and Contract for all LLM Gateway Providers.
Ensures zero-downtime, model-agnostic switching between Local and API providers.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Type
import json
import re


class LLMGatewayError(Exception):
    """Base exception for all LLM gateway communication, authentication, or validation failures."""
    pass


class LLMTimeoutError(LLMGatewayError):
    """Raised when an inference call exceeds configured latency SLA timeouts."""
    pass


class LLMValidationError(LLMGatewayError):
    """Raised when LLM output fails schema validation after retries."""
    pass


class LLMProvider(ABC):
    """
    Abstract interface for cybersecurity AI providers.
    All local (Ollama) and cloud (OpenAI, Gemini) adapters must implement this contract.
    """

    def __init__(self, model_name: str, config: Optional[Dict[str, Any]] = None):
        self.model_name = model_name
        self.config = config or {}

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 2000,
        **kwargs,
    ) -> str:
        """
        Generates text output for a given prompt and optional system context.
        """
        pass

    def generate_structured(
        self,
        prompt: str,
        schema_cls: Type[Any],
        system_prompt: Optional[str] = None,
        max_retries: int = 2,
        _original_prompt: Optional[str] = None,
    ) -> Any:
        """
        Generates response and validates it against the provided schema class.
        Includes built-in json sanitization, auto-unwrapping, and non-destructive retries.
        """
        base_prompt = _original_prompt or prompt
        structured_system = (
            f"{system_prompt or ''}\n\n"
            "CRITICAL INSTRUCTION: You MUST return strictly valid JSON matching the required schema. "
            "Do NOT include markdown formatting, explanations, or text outside the JSON object."
        ).strip()

        raw_response = self.generate(
            prompt=prompt,
            system_prompt=structured_system,
            temperature=0.0,
            format="json",
            schema_cls=schema_cls,
        )

        cleaned_json = self._extract_json(raw_response)

        try:
            data = json.loads(cleaned_json)
            # Auto-unwrap if model wrapped output in an extra container key (e.g. "threat_summary", "data", "result")
            if isinstance(data, dict) and len(data) == 1:
                single_key = next(iter(data))
                if isinstance(data[single_key], dict) and not hasattr(schema_cls, single_key):
                    data = data[single_key]
            if hasattr(schema_cls, "model_validate"):
                return schema_cls.model_validate(data)
            return schema_cls(**data)
        except Exception as e:
            if max_retries > 0:
                # Preserve the clean original prompt so critical evidence chunks are never lost or double-nested on retry
                retry_prompt = (
                    f"CRITICAL: Your previous JSON output was invalid.\n"
                    f"Error details: {str(e)}\n"
                    f"Return ONLY valid JSON matching the {schema_cls.__name__} schema directly at root (do NOT wrap in extra keys like 'threat_summary'):\n{base_prompt}"
                )
                return self.generate_structured(
                    prompt=retry_prompt,
                    schema_cls=schema_cls,
                    system_prompt=system_prompt,
                    max_retries=max_retries - 1,
                    _original_prompt=base_prompt,
                )
            raise LLMValidationError(f"Failed to parse and validate structured output: {e}\nRaw output: {raw_response}")

    @staticmethod
    def _extract_json(text: str) -> str:
        """Strips markdown code fences (```json ... ```) or extracts JSON object."""
        text = text.strip()
        # Check for ```json ... ``` or ``` ... ```
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
        if fence_match:
            return fence_match.group(1).strip()
        
        # Look for the outer-most { ... }
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return text[start:end + 1].strip()

        return text
