"""
Workflow 2: Structured Cybersecurity Entity Extraction.
Extracts CVEs, IOCs, Malware, Threat Actors, and Mitigations into a validated schema.
"""

from typing import Optional
from ..gateway.interface import LLMProvider
from ..schemas.cyber_entities import ExtractedCyberEntities
from ..prompts.extraction_prompts import EXTRACTION_SYSTEM_PROMPT, build_extraction_prompt


class CyberEntityExtractor:
    """Encapsulates entity extraction and JSON schema validation."""

    def __init__(self, provider: LLMProvider):
        self.provider = provider

    def extract(self, text: str) -> ExtractedCyberEntities:
        """
        Extracts verified cybersecurity entities from unstructured text.
        """
        if not text or not text.strip():
            raise ValueError("Input text cannot be empty.")

        prompt = build_extraction_prompt(text)

        entities = self.provider.generate_structured(
            prompt=prompt,
            schema_cls=ExtractedCyberEntities,
            system_prompt=EXTRACTION_SYSTEM_PROMPT,
        )
        return entities
