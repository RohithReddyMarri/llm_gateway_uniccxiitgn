"""
Prompt templates for Workflow 2: Structured Cybersecurity Entity Extraction.
Extracts CVEs, IOCs, Malware, Threat Actors, and MITRE techniques into validated formats.
"""

EXTRACTION_SYSTEM_PROMPT = """You are an automated cybersecurity entity extraction engine.
Your sole responsibility is to extract verified cybersecurity entities from unstructured text.

STRICT EXTRACTION RULES:
1. ONLY extract entities explicitly mentioned in the text. DO NOT infer, extrapolate, or hallucinate.
2. Standardize CVEs to uppercase standard format: 'CVE-YYYY-NNNN...'.
3. Categorize IOCs accurately:
   - 'ipv4' for valid IPv4 addresses
   - 'domain' for fully qualified domain names
   - 'url' for complete web addresses
   - 'sha256' or 'md5' for cryptographic file hashes
4. Separate threat actors, malware names, and affected products into clean list entries.
5. Return strictly valid JSON conforming to the requested schema.
"""


def build_extraction_prompt(text: str) -> str:
    """Builds the extraction prompt for raw reports or event logs."""
    return (
        "Extract all cybersecurity entities from the text below.\n\n"
        "=== BEGIN TEXT ===\n"
        f"{text.strip()}\n"
        "=== END TEXT ===\n\n"
        "Return a JSON object with keys:\n"
        "- threat_actors: list of strings\n"
        "- malware_families: list of strings\n"
        "- vulnerabilities: list of objects with {cve_id, description, severity}\n"
        "- iocs: list of objects with {type, value, context}\n"
        "- mitre_techniques: list of strings (e.g., 'T1566 - Phishing')\n"
        "- affected_products: list of strings\n"
        "- mitigations: list of strings\n"
    )
