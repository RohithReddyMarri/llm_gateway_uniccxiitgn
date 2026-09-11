"""
Mock LLM Provider for local zero-dependency testing, offline development,
and guaranteed repeatable presentations.
"""

from typing import Any, Dict, Optional
import json
from .interface import LLMProvider


class MockLLMProvider(LLMProvider):
    """
    Simulates high-quality, deterministic responses for all 3 workflows
    without requiring GPU hardware, Ollama, or external API keys.
    """

    def __init__(self, model_name: str = "mock-cyber-v1", config: Optional[Dict[str, Any]] = None):
        super().__init__(model_name=model_name, config=config)

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 2000,
    ) -> str:
        combined = f"{system_prompt or ''} {prompt}".lower()

        # Workflow 3: Investigation / RAG Grounding
        if "investigat" in combined or "retrieved evidence" in combined or "match_status" in combined:
            if "qakbot" in combined or "threatfox" in combined:
                return json.dumps({
                    "query_observation": "Abuse.ch ThreatFox and Shadowserver telemetry: QakBot malware infrastructure",
                    "match_status": "Exact",
                    "assessment_narrative": (
                        "The observed C2 IP 103.208.220.122 and domain check-finance-portal.org exactly match "
                        "known QakBot (QBot) distribution infrastructure reported in Abuse.ch ThreatFox feed "
                        "and Shadowserver telemetry. Activity is associated with cybercrime threat actor TA570."
                    ),
                    "potential_threat_actors": ["TA570"],
                    "associated_malware": ["QakBot"],
                    "associated_cves": [],
                    "confidence_level": "High",
                    "supporting_citations": [
                        {
                            "document_id": "THREATFOX-IOC-2026-904",
                            "relevance_score": 0.95,
                            "key_excerpt": "ThreatFox feed entry: C2 server 103.208.220.122 associated with QakBot payload staging.",
                            "observed_overlap": ["103.208.220.122"]
                        }
                    ],
                    "investigator_notes": "AI-assisted threat correlation grounded in ThreatFox and Shadowserver telemetry."
                }, indent=2)

            elif "lockbit" in combined or "citrix" in combined:
                return json.dumps({
                    "query_observation": "LockBit 3.0 Ransomware campaign exploiting Citrix Bleed",
                    "match_status": "Strong",
                    "assessment_narrative": (
                        "The observed threat indicators correlate with active exploitation of CVE-2023-4966 "
                        "(Citrix Bleed) by LockBit 3.0 ransomware affiliates. Historical NVD documentation "
                        "confirms sensitive session token leakage in unpatched NetScaler ADC appliances."
                    ),
                    "potential_threat_actors": ["LockBit 3.0 affiliates"],
                    "associated_malware": ["LockBit 3.0", "StealBit"],
                    "associated_cves": ["CVE-2023-4966"],
                    "confidence_level": "High",
                    "supporting_citations": [
                        {
                            "document_id": "NVD-CVE-2023-4966",
                            "relevance_score": 0.96,
                            "key_excerpt": "Sensitive information disclosure in NetScaler ADC and NetScaler Gateway when configured as an appliance.",
                            "observed_overlap": ["CVE-2023-4966"]
                        }
                    ],
                    "investigator_notes": "AI-assisted threat correlation. Terminate active sessions and apply vendor patch."
                }, indent=2)

            else:
                return json.dumps({
                    "query_observation": "Suspicious outbound traffic observed to 185.123.45.10 and execution of GhostPulse payload",
                    "match_status": "Exact",
                    "assessment_narrative": (
                        "The newly observed IP address (185.123.45.10) and binary signature exactly match "
                        "the historical campaign documented in UNICC Threat Advisory ENISA-2026-088. "
                        "Historical telemetry indicates this infrastructure is operated by the Lazarus Group "
                        "for secondary staging following exploitation of CVE-2024-38077. High probability of "
                        "active credential dumping on the affected endpoint."
                    ),
                    "potential_threat_actors": ["Lazarus Group"],
                    "associated_malware": ["GhostPulse", "DarkComet RAT"],
                    "associated_cves": ["CVE-2024-38077", "CVE-2024-21410"],
                    "confidence_level": "High",
                    "supporting_citations": [
                        {
                            "document_id": "ENISA-2026-088",
                            "relevance_score": 0.94,
                            "key_excerpt": "C2 node 185.123.45.10 was observed receiving telemetry from GhostPulse loader instances across European public sector targets.",
                            "observed_overlap": ["185.123.45.10", "GhostPulse"]
                        },
                        {
                            "document_id": "UNICC-HIST-LOG-2026-441",
                            "relevance_score": 0.88,
                            "key_excerpt": "Exchange server outbound connection to update-service-check[.]com resolving to 185.123.45.10.",
                            "observed_overlap": ["185.123.45.10"]
                        }
                    ],
                    "investigator_notes": "AI-assisted threat correlation grounded in ENISA and internal UNICC historical logs. Human investigator must confirm endpoint isolation."
                }, indent=2)

        # Workflow 1: Summarization
        elif "summariz" in combined or "executive summary" in combined:
            return json.dumps({
                "title": "Operation GhostPulse: Multi-Stage Ransomware Exploiting Microsoft Exchange",
                "executive_summary": (
                    "In August 2026, security telemetry identified a sophisticated campaign attributed "
                    "to the Lazarus Group exploiting CVE-2024-38077 and CVE-2024-21410 against UN partner entities. "
                    "The attackers utilized GhostPulse loader and DarkComet RAT before deploying HermeticRansom. "
                    "Immediate patching of on-premise Windows and Exchange servers is mandatory."
                ),
                "threat_level": "Critical",
                "affected_products": [
                    "Microsoft Exchange Server 2019",
                    "Windows Server 2022",
                    "Apache Log4j <= 2.14.1"
                ],
                "key_tactics": [
                    "Spear-phishing attachments",
                    "Exploitation of remote code execution vulnerabilities",
                    "LSASS credential dumping",
                    "C2 communication over encrypted HTTPS"
                ],
                "recommended_mitigations": [
                    "Apply Microsoft cumulative security updates for CVE-2024-38077 immediately.",
                    "Block communication to known C2 IP 185.123.45.10 and domain update-service-check[.]com.",
                    "Enforce multi-factor authentication (MFA) across all web-facing administrative portals."
                ],
                "confidence_rating": "High"
            }, indent=2)

        # Workflow 2: Entity Extraction
        else:
            if "qakbot" in combined or "threatfox" in combined:
                return json.dumps({
                    "threat_actors": ["TA570"],
                    "malware_families": ["QakBot"],
                    "vulnerabilities": [],
                    "iocs": [
                        {"type": "ipv4", "value": "103.208.220.122", "source_feed": "Abuse.ch ThreatFox", "context": "C2 server"},
                        {"type": "domain", "value": "check-finance-portal.org", "source_feed": "Shadowserver", "context": "Malicious payload domain"}
                    ],
                    "mitre_techniques": [
                        "T1566.001 - Spearphishing Attachment",
                        "T1071.001 - Web Protocols"
                    ],
                    "affected_products": [
                        "Microsoft Windows"
                    ],
                    "mitigations": [
                        "Block egress connections to 103.208.220.122.",
                        "Inspect perimeter gateways for traffic to check-finance-portal.org."
                    ]
                }, indent=2)

            elif "lockbit" in combined or "citrix" in combined:
                return json.dumps({
                    "threat_actors": ["LockBit 3.0 affiliates"],
                    "malware_families": ["LockBit 3.0", "StealBit"],
                    "vulnerabilities": [
                        {
                            "cve_id": "CVE-2023-4966",
                            "description": "Citrix Bleed sensitive information disclosure",
                            "severity": "Critical"
                        }
                    ],
                    "iocs": [
                        {"type": "ipv4", "value": "193.106.191.29", "source_feed": "AlienVault OTX", "context": "Staging server"}
                    ],
                    "mitre_techniques": [
                        "T1190 - Exploit Public-Facing Application"
                    ],
                    "affected_products": [
                        "Citrix NetScaler ADC",
                        "Citrix NetScaler Gateway"
                    ],
                    "mitigations": [
                        "Terminate active user sessions and rotate tokens.",
                        "Patch Citrix appliances immediately."
                    ]
                }, indent=2)

            else:
                return json.dumps({
                    "threat_actors": ["Lazarus Group"],
                    "malware_families": ["GhostPulse", "DarkComet RAT"],
                    "vulnerabilities": [
                        {
                            "cve_id": "CVE-2024-38077",
                            "description": "Windows Remote Desktop Licensing Service Remote Code Execution",
                            "severity": "Critical"
                        },
                        {
                            "cve_id": "CVE-2024-21410",
                            "description": "Microsoft Exchange Server Privilege Escalation Vulnerability",
                            "severity": "High"
                        }
                    ],
                    "iocs": [
                        {"type": "ipv4", "value": "185.123.45.10", "source_feed": "Abuse.ch ThreatFox", "context": "Primary Command and Control (C2) server"},
                        {"type": "domain", "value": "update-service-check.com", "source_feed": "Shadowserver", "context": "Malicious payload staging domain"}
                    ],
                    "mitre_techniques": [
                        "T1566.001 - Spearphishing Attachment",
                        "T1190 - Exploit Public-Facing Application",
                        "T1003.001 - OS Credential Dumping: LSASS Memory"
                    ],
                    "affected_products": [
                        "Microsoft Exchange Server",
                        "Windows Server 2022"
                    ],
                    "mitigations": [
                        "Apply vendor security patches for CVE-2024-38077.",
                        "Isolate endpoints showing outbound traffic to 185.123.45.10."
                    ]
                }, indent=2)
