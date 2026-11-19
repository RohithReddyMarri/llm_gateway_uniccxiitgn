"""
Schema for Workflow 2: Structured Cybersecurity Entity Extraction.
Converts unstructured threat intelligence text into standardized machine-readable entities.
"""

from typing import List, Optional, Any, Dict, Union
import json
import re

try:
    from pydantic import BaseModel, Field, field_validator
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    from dataclasses import dataclass, field, asdict


if PYDANTIC_AVAILABLE:
    class IndicatorOfCompromise(BaseModel):
        type: str = Field(..., description="IOC Type: ipv4, ipv6, domain, url, sha256, md5, filename")
        value: str = Field(..., description="The actual indicator value")
        source_feed: Optional[str] = Field(None, description="Feed origin: ThreatFox, AlienVault OTX, Shadowserver, NVD, etc.")
        context: Optional[str] = Field(None, description="Context or role (e.g., C2 server, phishing link)")

    class VulnerabilityReference(BaseModel):
        cve_id: str = Field(..., description="Standard CVE identifier, e.g., CVE-2024-1234")
        description: Optional[str] = Field(None, description="Brief description of the vulnerability")
        severity: Optional[str] = Field(None, description="Critical, High, Medium, Low")

        @field_validator("cve_id")
        def validate_cve_format(cls, v):
            clean = v.strip().upper()
            if not re.match(r"^CVE-\d{4}-\d{4,8}$", clean):
                raise ValueError(f"Invalid CVE format: '{clean}'. Expected 'CVE-YYYY-NNNN...'")
            return clean

    class ExtractedCyberEntities(BaseModel):
        threat_actors: List[str] = Field(default_factory=list, description="Names or aliases of threat actor groups")
        malware_families: List[str] = Field(default_factory=list, description="Malware families, ransomware strains, or tool names")
        vulnerabilities: List[VulnerabilityReference] = Field(default_factory=list, description="Referenced CVEs")
        iocs: List[IndicatorOfCompromise] = Field(default_factory=list, description="Indicators of Compromise")
        mitre_techniques: List[str] = Field(default_factory=list, description="Identified MITRE ATT&CK techniques")
        affected_products: List[str] = Field(default_factory=list, description="Targeted or vulnerable software/products")
        mitigations: List[str] = Field(default_factory=list, description="Recommended technical controls or patches")

        @field_validator("vulnerabilities", mode="before")
        @classmethod
        def sanitize_vulnerabilities(cls, v: Any):
            """Filters and coerces entries into valid VulnerabilityReference objects."""
            if not isinstance(v, list):
                return []
            valid = []
            for item in v:
                if isinstance(item, str):
                    cid = item.strip().upper()
                    if re.match(r"^CVE-\d{4}-\d{4,8}$", cid):
                        valid.append({"cve_id": cid})
                elif isinstance(item, dict):
                    cid = str(item.get("cve_id", "")).strip().upper()
                    if re.match(r"^CVE-\d{4}-\d{4,8}$", cid):
                        valid.append(item)
                elif hasattr(item, "cve_id"):
                    cid = str(getattr(item, "cve_id", "")).strip().upper()
                    if re.match(r"^CVE-\d{4}-\d{4,8}$", cid):
                        valid.append(item)
            return valid

        @field_validator("iocs", mode="before")
        @classmethod
        def sanitize_iocs(cls, v: Any):
            """Coerces strings or dicts into valid IndicatorOfCompromise objects."""
            if not isinstance(v, list):
                return []
            valid = []
            for item in v:
                if isinstance(item, str):
                    val = item.strip()
                    if not val:
                        continue
                    ioc_type = "unknown"
                    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", val):
                        ioc_type = "ipv4"
                    elif re.match(r"^[a-fA-F0-9]{64}$", val):
                        ioc_type = "sha256"
                    elif re.match(r"^[a-fA-F0-9]{32}$", val):
                        ioc_type = "md5"
                    elif re.match(r"^https?://", val, re.IGNORECASE):
                        ioc_type = "url"
                    elif "." in val and not val.endswith("."):
                        ioc_type = "domain"
                    valid.append({"type": ioc_type, "value": val})
                elif isinstance(item, dict) and "type" in item and "value" in item:
                    valid.append(item)
                elif hasattr(item, "type") and hasattr(item, "value"):
                    valid.append(item)
            return valid

        def to_dict(self):
            return self.model_dump()

        def to_json(self, indent: int = 2):
            return self.model_dump_json(indent=indent)

else:
    @dataclass
    class IndicatorOfCompromise:
        type: str
        value: str
        source_feed: Optional[str] = None
        context: Optional[str] = None

        def to_dict(self):
            return asdict(self)

    @dataclass
    class VulnerabilityReference:
        cve_id: str
        description: Optional[str] = None
        severity: Optional[str] = None

        def __post_init__(self):
            self.cve_id = self.cve_id.strip().upper()

        def to_dict(self):
            return asdict(self)

    @dataclass
    class ExtractedCyberEntities:
        threat_actors: List[str] = field(default_factory=list)
        malware_families: List[str] = field(default_factory=list)
        vulnerabilities: List[VulnerabilityReference] = field(default_factory=list)
        iocs: List[IndicatorOfCompromise] = field(default_factory=list)
        mitre_techniques: List[str] = field(default_factory=list)
        affected_products: List[str] = field(default_factory=list)
        mitigations: List[str] = field(default_factory=list)

        def to_dict(self):
            return {
                "threat_actors": self.threat_actors,
                "malware_families": self.malware_families,
                "vulnerabilities": [v.to_dict() if hasattr(v, 'to_dict') else v for v in self.vulnerabilities],
                "iocs": [i.to_dict() if hasattr(i, 'to_dict') else i for i in self.iocs],
                "mitre_techniques": self.mitre_techniques,
                "affected_products": self.affected_products,
                "mitigations": self.mitigations
            }

        def to_json(self, indent: int = 2):
            return json.dumps(self.to_dict(), indent=indent)

        @classmethod
        def model_validate(cls, obj):
            vulns = []
            for v in obj.get("vulnerabilities", []):
                if isinstance(v, str) and re.match(r"^CVE-\d{4}-\d{4,8}$", v.strip().upper()):
                    vulns.append(VulnerabilityReference(cve_id=v.strip().upper()))
                elif isinstance(v, dict):
                    vuln_keys = {"cve_id", "description", "severity"}
                    vulns.append(VulnerabilityReference(**{k: val for k, val in v.items() if k in vuln_keys}))
                elif hasattr(v, "cve_id"):
                    vulns.append(v)

            iocs = []
            for i in obj.get("iocs", []):
                if isinstance(i, str):
                    val = i.strip()
                    ioc_type = "ipv4" if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", val) else "domain"
                    iocs.append(IndicatorOfCompromise(type=ioc_type, value=val))
                elif isinstance(i, dict):
                    ioc_keys = {"type", "value", "source_feed", "context"}
                    iocs.append(IndicatorOfCompromise(**{k: val for k, val in i.items() if k in ioc_keys}))
                elif hasattr(i, "type"):
                    iocs.append(i)

            return cls(
                threat_actors=obj.get("threat_actors", []),
                malware_families=obj.get("malware_families", []),
                vulnerabilities=vulns,
                iocs=iocs,
                mitre_techniques=obj.get("mitre_techniques", []),
                affected_products=obj.get("affected_products", []),
                mitigations=obj.get("mitigations", [])
            )
