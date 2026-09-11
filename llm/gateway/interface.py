"""
Abstract Base Class defining the standard interface for all LLM providers.
Enables seamless switching between on-premise local models and external APIs.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Type
import json
import re


class LLMProvider(ABC):
    """Abstract interface that all model adapters (local or API) must implement."""

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
    ) -> str:
        """
        Generate raw text response from the underlying LLM.
        """
        pass

    def generate_structured(
        self,
        prompt: str,
        schema_cls: Type[Any],
        system_prompt: Optional[str] = None,
        max_retries: int = 2,
    ) -> Any:
        """
        Generates response and validates it against the provided schema class.
        Includes built-in json sanitization and fallback parsing.
        """
        structured_system = (
            f"{system_prompt or ''}\n\n"
            "CRITICAL INSTRUCTION: You MUST return strictly valid JSON matching the required schema. "
            "Do NOT include markdown formatting, explanations, or text outside the JSON object."
        ).strip()

        raw_response = self.generate(
            prompt=prompt,
            system_prompt=structured_system,
            temperature=0.0,
        )

        cleaned_json = self._extract_json(raw_response)

        try:
            data = json.loads(cleaned_json)
            if hasattr(schema_cls, "model_validate"):
                return schema_cls.model_validate(data)
            return schema_cls(**data)
        except Exception as e:
            if max_retries > 0:
                retry_prompt = (
                    f"Previous response was not valid JSON:\n{raw_response}\n\n"
                    f"Error: {str(e)}\n\n"
                    f"Please re-generate the JSON object correctly for:\n{prompt}"
                )
                return self.generate_structured(
                    prompt=retry_prompt,
                    schema_cls=schema_cls,
                    system_prompt=system_prompt,
                    max_retries=max_retries - 1,
                )
            raise ValueError(f"Failed to parse and validate structured output: {e}\nRaw output: {raw_response}")

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
