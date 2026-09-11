"""
Schema for Workflow 2: Structured Cybersecurity Entity Extraction.
Converts unstructured threat intelligence text into standardized machine-readable entities.
"""

from typing import List, Optional
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
            vulns = [VulnerabilityReference(**v) if isinstance(v, dict) else v for v in obj.get("vulnerabilities", [])]
            iocs = [IndicatorOfCompromise(**i) if isinstance(i, dict) else i for i in obj.get("iocs", [])]
            return cls(
                threat_actors=obj.get("threat_actors", []),
                malware_families=obj.get("malware_families", []),
                vulnerabilities=vulns,
                iocs=iocs,
                mitre_techniques=obj.get("mitre_techniques", []),
                affected_products=obj.get("affected_products", []),
                mitigations=obj.get("mitigations", [])
            )
