"""
Curated Ground-Truth Benchmark Dataset for Team 3 LLM Intelligence & Evaluation.
Used to quantitatively assess:
1. Entity Extraction F1 (CVEs, IOCs, Malware Families, Threat Actors)
2. Evidence Groundedness (Citations vs. Hallucinated IDs)
3. Patch Identification Precision (Task 3.0: Status, Affected/Fixed Versions, Remediations)
4. End-to-End Investigation Reasoning
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
        "ground_truth_patch": {
            "patch_status": "Available",
            "affected_versions": ["Windows Remote Desktop Licensing", "Microsoft Exchange Server"],
            "fixed_versions": ["Cumulative Security Updates"],
            "remediation_workarounds": ["Enforce MFA", "Apply vendor security updates"],
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
        "ground_truth_patch": {
            "patch_status": "Available",
            "affected_versions": ["Citrix NetScaler ADC", "NetScaler Gateway"],
            "fixed_versions": ["NetScaler Firmware Update"],
            "remediation_workarounds": ["Terminating active sessions", "Kill established sessions"],
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
        "ground_truth_patch": {
            "patch_status": "Not Applicable",
            "affected_versions": [],
            "fixed_versions": [],
            "remediation_workarounds": ["Block traffic to malicious C2 node", "Inspect process lineages"],
        },
        "retrieved_evidence": [
            {
                "document_id": "THREATFOX-IOC-2026-904",
                "relevance_score": 0.95,
                "content": "ThreatFox feed entry: C2 server 103.208.220.122 associated with QakBot payload staging.",
            }
        ],
        "expected_match_status": "Exact",
    },
    {
        "case_id": "TC-CYBER-004",
        "description": "Zero-Day remote exploit in logging daemon without vendor patch",
        "raw_text": (
            "Zero-Day vulnerability warning: Security researchers reported active in-the-wild exploitation "
            "of an unpatched remote code execution vulnerability (CVE-2026-99120) affecting OpenLogAgent versions 3.0 to 3.4.1. "
            "No official vendor patch has been released yet. Threat group VoltTyphoon has been observed using this exploit. "
            "Immediate workaround: administrators must disable the remote telemetry listener on port 9200 and isolate vulnerable hosts."
        ),
        "ground_truth_entities": {
            "threat_actors": ["VoltTyphoon"],
            "malware_families": [],
            "cves": ["CVE-2026-99120"],
            "iocs": ["port 9200"],
        },
        "ground_truth_patch": {
            "patch_status": "Workaround Only",
            "affected_versions": ["OpenLogAgent versions 3.0 to 3.4.1", "OpenLogAgent"],
            "fixed_versions": [],
            "remediation_workarounds": ["Disable remote telemetry listener on port 9200", "Isolate vulnerable hosts"],
        },
        "retrieved_evidence": [
            {
                "document_id": "CISA-ALERT-2026-012",
                "relevance_score": 0.91,
                "content": "Advisory on active exploitation of OpenLogAgent zero-day CVE-2026-99120. Vendor security patch is pending.",
            }
        ],
        "expected_match_status": "Strong",
    }
]
