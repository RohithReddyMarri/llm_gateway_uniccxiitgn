"""
Workflow 2: Structured Cybersecurity Entity Extraction.
Extracts CVEs, IOCs, Malware, Threat Actors, and Mitigations into a validated schema.
Includes automatic fallback to deterministic regex extraction if LLM is offline or times out.
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
        Falls back gracefully to deterministic pattern extraction if LLM fails.
        """
        if not text or not text.strip():
            raise ValueError("Input text cannot be empty.")

        prompt = build_extraction_prompt(text)

        try:
            entities = self.provider.generate_structured(
                prompt=prompt,
                schema_cls=ExtractedCyberEntities,
                system_prompt=EXTRACTION_SYSTEM_PROMPT,
            )
            return entities
        except Exception as e:
            # Fallback to offline regex-based IOC and CVE extractor
            try:
                from ..gateway.ioc_extractor import extract_iocs
                regex_results = extract_iocs(text)
                cves = [{"cve_id": c} for c in regex_results.get("cves", [])]
                iocs = []
                for ip in regex_results.get("ips", []):
                    iocs.append({"type": "ipv4", "value": ip})
                for domain in regex_results.get("domains", []):
                    iocs.append({"type": "domain", "value": domain})
                for h in regex_results.get("hashes", []):
                    h_type = "sha256" if len(h) == 64 else ("sha1" if len(h) == 40 else "md5")
                    iocs.append({"type": h_type, "value": h})

                return ExtractedCyberEntities.model_validate({
                    "threat_actors": [],
                    "malware_families": [],
                    "vulnerabilities": cves,
                    "iocs": iocs,
                    "mitre_techniques": [],
                    "affected_products": [],
                    "mitigations": ["Deterministic regex fallback applied due to LLM unavailable."]
                })
            except Exception:
                raise e
