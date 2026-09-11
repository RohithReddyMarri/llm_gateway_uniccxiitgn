"""
Schema for Workflow 1: Report Summarization.
Represents an executive and technical summary of a cybersecurity report.
"""

from typing import List, Optional
import json

try:
    from pydantic import BaseModel, Field
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    from dataclasses import dataclass, field, asdict

if PYDANTIC_AVAILABLE:
    class ThreatReportSummary(BaseModel):
        title: str = Field(..., description="Concise, descriptive title of the threat report")
        executive_summary: str = Field(..., description="High-level summary suitable for leadership and investigators")
        threat_level: str = Field("Medium", description="Assessed threat level: Critical, High, Medium, Low, or Informational")
        affected_products: List[str] = Field(default_factory=list, description="Targeted software, operating systems, or hardware")
        key_tactics: List[str] = Field(default_factory=list, description="Primary attack tactics (e.g., Phishing, Credential Theft)")
        recommended_mitigations: List[str] = Field(default_factory=list, description="Actionable technical and operational mitigations")
        confidence_rating: str = Field("High", description="Confidence rating: High, Medium, Low")

        def to_dict(self):
            return self.model_dump()

        def to_json(self, indent: int = 2):
            return self.model_dump_json(indent=indent)

else:
    @dataclass
    class ThreatReportSummary:
        title: str
        executive_summary: str
        threat_level: str = "Medium"
        affected_products: List[str] = field(default_factory=list)
        key_tactics: List[str] = field(default_factory=list)
        recommended_mitigations: List[str] = field(default_factory=list)
        confidence_rating: str = "High"

        def to_dict(self):
            return asdict(self)

        def to_json(self, indent: int = 2):
            return json.dumps(self.to_dict(), indent=indent)

        @classmethod
        def model_validate(cls, obj):
            return cls(**obj)
