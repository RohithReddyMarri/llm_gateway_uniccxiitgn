"""
Curated Ground-Truth Benchmark Dataset for LLM Intelligence & Evaluation.
Grounded directly in authentic knowledge-base records (CISA KEV, NVD, EPSS, Abuse.ch)
from the UNICC x IITGN Capstone corpus.

Calibrated to evaluate all 5 UNICC Historical Threat Match Tiers:
- EXACT: Identical observables & verified CVE correlation
- STRONG: Overlapping campaign infrastructure & technique signatures
- PARTIAL: Shared commodity malware without verified actor attribution
- WEAK: Low-fidelity incidental overlap (generic administrative tools)
- UNSUPPORTED: Benign operational activity with zero threat overlap
"""

BENCHMARK_CASES = [
    {
        "case_id": "TC-CYBER-001",
        "expected_tier": "Exact",
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
            "affected_versions": ["Microsoft Exchange Server", "Windows Remote Desktop Licensing"],
            "fixed_versions": ["Cumulative Security Updates", "Microsoft Exchange Server 2019 CU14"],
            "remediation_workarounds": ["Enforce MFA", "Apply vendor security updates"],
        },
        "retrieved_evidence": [
            {
                "document_id": "CVE-2024-21410_KEV",
                "relevance_score": 0.95,
                "content": (
                    "Vulnerability: Microsoft Exchange Server Privilege Escalation Vulnerability | "
                    "Vendor: Microsoft | Product: Exchange Server | Required Action: Apply mitigations "
                    "per vendor instructions or discontinue use of the product if mitigations are unavailable. | "
                    "Notes: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21410"
                ),
            },
            {
                "document_id": "CVE-2024-38077_KEV",
                "relevance_score": 0.91,
                "content": (
                    "Vulnerability: Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability | "
                    "Vendor: Microsoft | Product: Windows Server | Required Action: Apply cumulative security updates "
                    "or disable remote desktop licensing role if unused."
                ),
            },
        ],
        "expected_match_status": "Exact",
    },
    {
        "case_id": "TC-CYBER-002",
        "expected_tier": "Strong",
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
            "fixed_versions": ["NetScaler Firmware Update", "NetScaler ADC Release 14.1"],
            "remediation_workarounds": ["Terminating active sessions", "Kill all active and persistent sessions"],
        },
        "retrieved_evidence": [
            {
                "document_id": "CVE-2023-4966_KEV",
                "relevance_score": 0.965,
                "content": (
                    "Vulnerability: Citrix NetScaler ADC and NetScaler Gateway Buffer Overflow Vulnerability | "
                    "Vendor: Citrix | Product: NetScaler ADC and NetScaler Gateway | "
                    "Required Action: Apply mitigations and kill all active and persistent sessions per vendor instructions "
                    "[https://www.netscaler.com/blog/news/cve-2023-4966-critical-security-update-now-available-for-netscaler-adc-and-netscaler-gateway/]"
                ),
            },
            {
                "document_id": "CVE-2023-4966",
                "relevance_score": 0.92,
                "content": (
                    "Sensitive information disclosure in NetScaler ADC and NetScaler Gateway when configured as a "
                    "Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) or AAA virtual server."
                ),
            },
        ],
        "expected_match_status": "Strong",
    },
    {
        "case_id": "TC-CYBER-003",
        "expected_tier": "Partial",
        "description": "Commodity RAT execution from uncorroborated infrastructure",
        "raw_text": (
            "SOC Alert: Suspicious outbound HTTPS beaconing detected from endpoint WS-044 to 198.51.100.88. "
            "Host telemetry revealed in-memory execution of commodity DarkComet RAT payload. "
            "No active exploitation of known CVEs observed; attribution to specific APT groups remains unconfirmed."
        ),
        "ground_truth_entities": {
            "threat_actors": [],
            "malware_families": ["DarkComet RAT"],
            "cves": [],
            "iocs": ["198.51.100.88", "WS-044"],
        },
        "ground_truth_patch": {
            "patch_status": "Not Applicable",
            "affected_versions": [],
            "fixed_versions": [],
            "remediation_workarounds": ["Isolate host WS-044", "Block IP 198.51.100.88 at perimeter firewall"],
        },
        "retrieved_evidence": [
            {
                "document_id": "ENISA-HIST-RAT-092",
                "relevance_score": 0.62,
                "content": (
                    "Threat report: Commodity DarkComet RAT instances observed utilized across various opportunistic "
                    "crimeware campaigns. Shared infrastructure is rare; indicators typically isolated."
                ),
            }
        ],
        "expected_match_status": "Partial",
    },
    {
        "case_id": "TC-CYBER-004",
        "expected_tier": "Weak",
        "description": "Living-off-the-land administrative utility usage",
        "raw_text": (
            "Security telemetry alert: Systems administrator executed certutil.exe and PowerShell v5.1 "
            "on administrative server SRV-MGMT-01. Script executed remote file copy over SMB port 445. "
            "No known malware hashes or command-and-control communication detected."
        ),
        "ground_truth_entities": {
            "threat_actors": [],
            "malware_families": [],
            "cves": [],
            "iocs": ["SRV-MGMT-01", "port 445"],
        },
        "ground_truth_patch": {
            "patch_status": "Not Applicable",
            "affected_versions": [],
            "fixed_versions": [],
            "remediation_workarounds": ["Review PowerShell Script Block Logging", "Restrict certutil download functionality"],
        },
        "retrieved_evidence": [
            {
                "document_id": "UNICC-SYS-BASELINE-401",
                "relevance_score": 0.38,
                "content": (
                    "Administrative operations guide: Scheduled IT management routines commonly invoke certutil "
                    "for internal certificate authority renewal across management clusters."
                ),
            }
        ],
        "expected_match_status": "Weak",
    },
    {
        "case_id": "TC-CYBER-005",
        "expected_tier": "Unsupported",
        "description": "Routine scheduled database backup and log rotation",
        "raw_text": (
            "Infrastructure event notification: Scheduled automated backup script initiated on database cluster DB-PROD-02. "
            "System logged tar archive compression and rsync transfer to internal storage node 10.0.4.15 on port 22. "
            "CPU utilization peaked at 88% during compression. All operations completed normally with zero security anomalies."
        ),
        "ground_truth_entities": {
            "threat_actors": [],
            "malware_families": [],
            "cves": [],
            "iocs": ["DB-PROD-02", "10.0.4.15", "port 22"],
        },
        "ground_truth_patch": {
            "patch_status": "Not Applicable",
            "affected_versions": [],
            "fixed_versions": [],
            "remediation_workarounds": ["Routine operational logging", "No security remediation required"],
        },
        "retrieved_evidence": [],
        "expected_match_status": "Unsupported",
    }
]
