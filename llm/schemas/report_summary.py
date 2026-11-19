"""
Schema for Workflow 1: Report Summarization.
Represents an executive and technical summary of a cybersecurity report.
"""

from typing import List, Optional, Any, Union
import json

try:
    from pydantic import BaseModel, Field, field_validator
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

        @field_validator("affected_products", "key_tactics", "recommended_mitigations", mode="before")
        @classmethod
        def coerce_strings_to_list(cls, v: Any):
            if isinstance(v, str):
                if "," in v:
                    return [item.strip() for item in v.split(",") if item.strip()]
                return [v.strip()] if v.strip() else []
            return v or []

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
            def _to_list(val):
                if isinstance(val, str):
                    return [x.strip() for x in val.split(",") if x.strip()]
                return val or []

            return cls(
                title=obj.get("title", ""),
                executive_summary=obj.get("executive_summary", ""),
                threat_level=obj.get("threat_level", "Medium"),
                affected_products=_to_list(obj.get("affected_products", [])),
                key_tactics=_to_list(obj.get("key_tactics", [])),
                recommended_mitigations=_to_list(obj.get("recommended_mitigations", [])),
                confidence_rating=obj.get("confidence_rating", "High"),
            )
