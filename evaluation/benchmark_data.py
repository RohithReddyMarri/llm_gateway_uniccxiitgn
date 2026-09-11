"""
Curated Ground-Truth Benchmark Dataset for Team 3 Evaluation.
Used to quantitatively assess Extraction F1, Summarization completeness, and Grounding.
"""

BENCHMARK_CASES = [
    {
        "case_id": "TC-CYBER-001",
        "description": "Lazarus Group campaign targeting Exchange and Windows Server",
        "raw_text": (
            "During recent operations in Q3 2026, the Lazarus Group targeted UN partner organizations "
            "using GhostPulse malware and DarkComet RAT. Attackers achieved initial access by exploiting "
            "CVE-2024-38077 (CVSS 9.8) in Windows Remote Desktop Licensing and CVE-2024-21410 in Microsoft Exchange Server. "
            "Exfiltration and C2 traffic were routed through IP 185.123.45.10 and staging domain update-service-check.com. "
            "Organizations are strongly advised to apply vendor cumulative security updates and enforce MFA."
        ),
        "ground_truth_entities": {
            "threat_actors": ["Lazarus Group"],
            "malware_families": ["GhostPulse", "DarkComet RAT"],
            "cves": ["CVE-2024-38077", "CVE-2024-21410"],
            "iocs": ["185.123.45.10", "update-service-check.com"],
        },
        "retrieved_evidence": [
            {
                "document_id": "ENISA-2026-088",
                "relevance_score": 0.94,
                "content": "C2 node 185.123.45.10 was observed receiving telemetry from GhostPulse loader instances.",
            },
            {
                "document_id": "UNICC-HIST-LOG-2026-441",
                "relevance_score": 0.88,
                "content": "Outbound HTTP connection to update-service-check.com resolving to 185.123.45.10.",
            },
        ],
        "expected_match_status": "Exact",
    },
    {
        "case_id": "TC-CYBER-002",
        "description": "LockBit 3.0 Ransomware campaign exploiting Citrix Bleed",
        "raw_text": (
            "Cybersecurity advisory: LockBit 3.0 ransomware affiliates have been actively exploiting "
            "CVE-2023-4966 (Citrix Bleed) in Citrix NetScaler ADC and Gateway appliances. "
            "Compromised hosts communicated with staging server 193.106.191.29 and dropped StealBit payload. "
            "Mitigation requires terminating active sessions and patching to current NetScaler firmware."
        ),
        "ground_truth_entities": {
            "threat_actors": ["LockBit 3.0 affiliates"],
            "malware_families": ["LockBit 3.0", "StealBit"],
            "cves": ["CVE-2023-4966"],
            "iocs": ["193.106.191.29"],
        },
        "retrieved_evidence": [
            {
                "document_id": "NVD-CVE-2023-4966",
                "relevance_score": 0.96,
                "content": "Sensitive information disclosure in NetScaler ADC and NetScaler Gateway when configured as an appliance.",
            }
        ],
        "expected_match_status": "Strong",
    },
    {
        "case_id": "TC-CYBER-003",
        "description": "Abuse.ch ThreatFox and Shadowserver feed: QakBot malware infrastructure",
        "raw_text": (
            "Threat intelligence alert: Abuse.ch ThreatFox telemetry and Shadowserver reporting identified "
            "active QakBot (QBot) distribution attributed to threat actor TA570. The campaign drops loader payloads "
            "communicating with Command and Control node 103.208.220.122 and domain check-finance-portal.org. "
            "Defenders are urged to block traffic to these indicators and inspect process lineages."
        ),
        "ground_truth_entities": {
            "threat_actors": ["TA570"],
            "malware_families": ["QakBot"],
            "cves": [],
            "iocs": ["103.208.220.122", "check-finance-portal.org"],
        },
        "retrieved_evidence": [
            {
                "document_id": "THREATFOX-IOC-2026-904",
                "relevance_score": 0.95,
                "content": "ThreatFox feed entry: C2 server 103.208.220.122 associated with QakBot payload staging.",
            }
        ],
        "expected_match_status": "Exact",
    }
]

