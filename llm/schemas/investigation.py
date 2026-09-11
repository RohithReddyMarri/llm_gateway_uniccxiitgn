"""
Schema for Workflow 3: Evidence-Grounded Threat Investigation (RAG).
Synthesizes retrieved historical evidence into an analyst-facing report with strict citations.
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
    class EvidenceCitation(BaseModel):
        document_id: str = Field(..., description="ID or title of the historical report/log")
        relevance_score: Optional[float] = Field(None, description="Similarity score from Team 2 retrieval")
        key_excerpt: str = Field(..., description="Direct quote or specific evidence extracted from source")
        observed_overlap: List[str] = Field(default_factory=list, description="Shared indicators (e.g. same IP or CVE)")

    class InvestigationResult(BaseModel):
        query_observation: str = Field(..., description="The observed suspicious indicator or threat under review")
        match_status: str = Field(..., description="Match category: Exact, Strong, Partial, Weak, or Unsupported")
        assessment_narrative: str = Field(..., description="Synthesized contextual assessment grounded in evidence")
        potential_threat_actors: List[str] = Field(default_factory=list, description="Identified threat actors in historical matches")
        associated_malware: List[str] = Field(default_factory=list, description="Associated malware families in evidence")
        associated_cves: List[str] = Field(default_factory=list, description="Associated CVE vulnerabilities")
        confidence_level: str = Field("Medium", description="Confidence level: High, Medium, Low")
        supporting_citations: List[EvidenceCitation] = Field(default_factory=list, description="Documented evidence citations")
        investigator_notes: str = Field(
            default="AI-assisted assessment. Requires verification by human cybersecurity analyst.",
            description="Human-in-the-loop reminder"
        )

        def to_dict(self):
            return self.model_dump()

        def to_json(self, indent: int = 2):
            return self.model_dump_json(indent=indent)

else:
    @dataclass
    class EvidenceCitation:
        document_id: str
        key_excerpt: str
        relevance_score: Optional[float] = None
        observed_overlap: List[str] = field(default_factory=list)

        def to_dict(self):
            return asdict(self)

    @dataclass
    class InvestigationResult:
        query_observation: str
        match_status: str
        assessment_narrative: str
        potential_threat_actors: List[str] = field(default_factory=list)
        associated_malware: List[str] = field(default_factory=list)
        associated_cves: List[str] = field(default_factory=list)
        confidence_level: str = "Medium"
        supporting_citations: List[EvidenceCitation] = field(default_factory=list)
        investigator_notes: str = "AI-assisted assessment. Requires verification by human cybersecurity analyst."

        def to_dict(self):
            return {
                "query_observation": self.query_observation,
                "match_status": self.match_status,
                "assessment_narrative": self.assessment_narrative,
                "potential_threat_actors": self.potential_threat_actors,
                "associated_malware": self.associated_malware,
                "associated_cves": self.associated_cves,
                "confidence_level": self.confidence_level,
                "supporting_citations": [c.to_dict() if hasattr(c, 'to_dict') else c for c in self.supporting_citations],
                "investigator_notes": self.investigator_notes
            }

        def to_json(self, indent: int = 2):
            return json.dumps(self.to_dict(), indent=indent)

        @classmethod
        def model_validate(cls, obj):
            citations = [EvidenceCitation(**c) if isinstance(c, dict) else c for c in obj.get("supporting_citations", [])]
            return cls(
                query_observation=obj.get("query_observation", ""),
                match_status=obj.get("match_status", "Unsupported"),
                assessment_narrative=obj.get("assessment_narrative", ""),
                potential_threat_actors=obj.get("potential_threat_actors", []),
                associated_malware=obj.get("associated_malware", []),
                associated_cves=obj.get("associated_cves", []),
                confidence_level=obj.get("confidence_level", "Medium"),
                supporting_citations=citations,
                investigator_notes=obj.get("investigator_notes", "AI-assisted assessment. Human review required.")
            )
