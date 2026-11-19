"""
Schema for Workflow 3: Evidence-Grounded Threat Investigation (RAG).
Maps observed threats against retrieved historical incident records.
"""

from typing import List, Optional, Union, Any, Dict
import json

try:
    from pydantic import BaseModel, Field, field_validator
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    from dataclasses import dataclass, field, asdict


if PYDANTIC_AVAILABLE:
    class EvidenceCitation(BaseModel):
        document_id: str = Field(..., description="ID or title of the cited historical document")
        key_excerpt: str = Field(..., description="Verbatim or precise quote proving the correlation")
        relevance_score: Optional[float] = Field(None, description="Similarity score or retrieval confidence")
        observed_overlap: List[str] = Field(default_factory=list, description="Specific matched observables (IPs, hashes, CVEs)")

        @field_validator("observed_overlap", mode="before")
        @classmethod
        def coerce_observed_overlap(cls, v: Any):
            if v is None:
                return []
            if isinstance(v, str):
                v_clean = v.strip()
                if not v_clean:
                    return []
                if "," in v_clean:
                    return [item.strip() for item in v_clean.split(",") if item.strip()]
                return [v_clean]
            if isinstance(v, (list, tuple, set)):
                return [str(x).strip() for x in v if str(x).strip()]
            return [str(v)]

        def to_dict(self):
            return self.model_dump()

    class PatchDetails(BaseModel):
        patch_status: str = Field(
            "Unknown",
            description="Categorical patch availability: 'Available', 'No Official Patch', 'Workaround Only', or 'Not Applicable'"
        )
        affected_versions: List[str] = Field(
            default_factory=list,
            description="Specific vulnerable software products, packages, and version ranges"
        )
        fixed_versions: List[str] = Field(
            default_factory=list,
            description="Official patch versions, security update bulletins (e.g. MS17-010), or patched releases"
        )
        remediation_workarounds: List[str] = Field(
            default_factory=list,
            description="Official mitigations or workarounds if unpatched or prior to update (e.g. disable protocol)"
        )

        @field_validator("affected_versions", "fixed_versions", "remediation_workarounds", mode="before")
        @classmethod
        def coerce_strings_to_list(cls, v: Any):
            if isinstance(v, str):
                return [v] if v else []
            return v or []

        def to_dict(self):
            return self.model_dump()

    class InvestigationResult(BaseModel):
        query_observation: str = Field(..., description="The observed suspicious indicator or threat under review")
        match_status: str = Field(..., description="Match category: Exact, Strong, Partial, Weak, or Unsupported")
        assessment_narrative: str = Field(..., description="Synthesized contextual assessment grounded in evidence")
        potential_threat_actors: Union[List[str], str] = Field(default_factory=list, description="Identified threat actors in historical matches")
        associated_malware: Union[List[str], str] = Field(default_factory=list, description="Associated malware families in evidence")
        associated_cves: Union[List[str], str] = Field(default_factory=list, description="Associated CVE vulnerabilities")
        mitre_tactics: Union[List[str], str] = Field(default_factory=list, description="Identified MITRE ATT&CK tactics")
        associated_mitre_tactics: Union[List[str], str] = Field(default_factory=list, description="Alias for mitre_tactics")
        patch_details: PatchDetails = Field(
            default_factory=PatchDetails,
            description="Details on patch availability, affected versions, fixed versions, and remediation workarounds"
        )
        confidence_level: str = Field("Medium", description="Confidence level: High, Medium, Low")
        supporting_citations: List[EvidenceCitation] = Field(default_factory=list, description="Documented evidence citations")
        investigator_notes: str = Field(
            default="AI-assisted assessment. Requires verification by human cybersecurity analyst.",
            description="Human-in-the-loop reminder"
        )

        @field_validator("potential_threat_actors", "associated_malware", "associated_cves", "mitre_tactics", "associated_mitre_tactics", mode="before")
        @classmethod
        def coerce_strings_to_list(cls, v: Any):
            if isinstance(v, str):
                return [v] if v else []
            return v or []

        @field_validator("patch_details", mode="before")
        @classmethod
        def coerce_patch_details(cls, v: Any):
            if v is None:
                return PatchDetails()
            if isinstance(v, dict):
                return PatchDetails(**v)
            return v

        def to_dict(self):
            d = self.model_dump()
            if not d.get("associated_mitre_tactics") and d.get("mitre_tactics"):
                d["associated_mitre_tactics"] = d["mitre_tactics"]
            if not d.get("mitre_tactics") and d.get("associated_mitre_tactics"):
                d["mitre_tactics"] = d["associated_mitre_tactics"]
            return d

        def to_json(self, indent: int = 2):
            return json.dumps(self.to_dict(), indent=indent)

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
    class PatchDetails:
        patch_status: str = "Unknown"
        affected_versions: List[str] = field(default_factory=list)
        fixed_versions: List[str] = field(default_factory=list)
        remediation_workarounds: List[str] = field(default_factory=list)

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
        mitre_tactics: List[str] = field(default_factory=list)
        associated_mitre_tactics: List[str] = field(default_factory=list)
        patch_details: PatchDetails = field(default_factory=PatchDetails)
        confidence_level: str = "Medium"
        supporting_citations: List[EvidenceCitation] = field(default_factory=list)
        investigator_notes: str = "AI-assisted assessment. Requires verification by human cybersecurity analyst."

        def to_dict(self):
            tactics = self.associated_mitre_tactics or self.mitre_tactics
            return {
                "query_observation": self.query_observation,
                "match_status": self.match_status,
                "assessment_narrative": self.assessment_narrative,
                "potential_threat_actors": self.potential_threat_actors,
                "associated_malware": self.associated_malware,
                "associated_cves": self.associated_cves,
                "mitre_tactics": tactics,
                "associated_mitre_tactics": tactics,
                "patch_details": self.patch_details.to_dict() if hasattr(self.patch_details, "to_dict") else self.patch_details,
                "confidence_level": self.confidence_level,
                "supporting_citations": [c.to_dict() if hasattr(c, 'to_dict') else c for c in self.supporting_citations],
                "investigator_notes": self.investigator_notes
            }

        def to_json(self, indent: int = 2):
            return json.dumps(self.to_dict(), indent=indent)

        @classmethod
        def model_validate(cls, obj):
            citation_keys = {"document_id", "key_excerpt", "relevance_score", "observed_overlap"}
            citations = []
            for c in obj.get("supporting_citations", []):
                if isinstance(c, dict):
                    filt = {k: v for k, v in c.items() if k in citation_keys}
                    if "observed_overlap" in filt:
                        oo = filt["observed_overlap"]
                        if isinstance(oo, str):
                            filt["observed_overlap"] = [oo] if oo.strip() else []
                        elif not isinstance(oo, list):
                            filt["observed_overlap"] = list(oo) if oo else []
                    citations.append(EvidenceCitation(**filt))
                else:
                    citations.append(c)
            raw_patch = obj.get("patch_details", {})
            patch_keys = {"patch_status", "affected_versions", "fixed_versions", "remediation_workarounds"}
            patch = (
                PatchDetails(**{k: v for k, v in raw_patch.items() if k in patch_keys})
                if isinstance(raw_patch, dict)
                else (raw_patch or PatchDetails())
            )
            tactics = obj.get("associated_mitre_tactics") or obj.get("mitre_tactics", [])
            if isinstance(tactics, str):
                tactics = [tactics] if tactics else []
            return cls(
                query_observation=obj.get("query_observation", ""),
                match_status=obj.get("match_status", "Unsupported"),
                assessment_narrative=obj.get("assessment_narrative", ""),
                potential_threat_actors=obj.get("potential_threat_actors", []),
                associated_malware=obj.get("associated_malware", []),
                associated_cves=obj.get("associated_cves", []),
                mitre_tactics=tactics,
                associated_mitre_tactics=tactics,
                patch_details=patch,
                confidence_level=obj.get("confidence_level", "Medium"),
                supporting_citations=citations,
                investigator_notes=obj.get("investigator_notes", "AI-assisted assessment. Human review required.")
            )
