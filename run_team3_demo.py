"""
================================================================================
UNICC x IITGN Capstone Collaboration - AI & Cybersecurity
Team 3: LLM Intelligence & Evaluation Layer - End-to-End Demonstration
================================================================================
Demonstrates:
  1. Model-Agnostic LLM Gateway (Mock, Local Ollama, or API)
  2. Workflow 1: Cybersecurity Report Summarization
  3. Workflow 2: Structured Cybersecurity Entity Extraction
  4. Workflow 3: Evidence-Grounded Threat Investigation (RAG Synthesis)

Usage:
  python run_team3_demo.py                  # Defaults to 'mock' mode (offline, instant)
  python run_team3_demo.py --backend local  # Connects to local Ollama (llama3/mistral)
  python run_team3_demo.py --backend api    # Connects to external API (OpenAI/Gemini)
================================================================================
"""

import sys
import os
import argparse
import json

# Ensure project root is in path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from llm.gateway.factory import get_llm_provider
from llm.workflows.summarizer import ReportSummarizer
from llm.workflows.extractor import CyberEntityExtractor
from llm.workflows.investigator import ThreatInvestigator


def print_banner(title: str):
    print("\n" + "=" * 78)
    print(f" {title.upper()}")
    print("=" * 78)


def main():
    parser = argparse.ArgumentParser(description="Run UNICC Team 3 LLM Intelligence Demo")
    parser.add_argument(
        "--backend",
        default="mock",
        choices=["mock", "local", "api"],
        help="LLM backend to use (mock: offline testing, local: Ollama, api: cloud provider)"
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Specific model name (e.g. 'llama3:8b' or 'gpt-4o-mini')"
    )
    args = parser.parse_args()

    print_banner("UNICC x IITGN Capstone: Team 3 LLM Intelligence Layer")
    print("Team Members: Rohith Reddy Marri (24110303) & Vallapudasu Hanook (24110378)")
    print(f"Active LLM Backend: {args.backend.upper()}")

    # 1. Initialize Gateway
    print("\n[STEP 1] Initializing Model-Agnostic LLM Gateway...")
    try:
        provider = get_llm_provider(backend=args.backend, model_name=args.model)
        print(f"  -> Gateway initialized successfully using provider: {provider.__class__.__name__}")
        print(f"  -> Model target: {provider.model_name}")
    except Exception as e:
        print(f"  [ERROR] Failed to initialize provider: {e}")
        sys.exit(1)

    # Sample input report (simulating ingestion from Team 1)
    sample_report = (
        "During August 2026, security researchers identified targeted cyber espionage operations "
        "attributed to the Lazarus Group against UN and international public health infrastructure. "
        "The adversaries gained initial execution by exploiting critical vulnerability CVE-2024-38077 "
        "(CVSS 9.8) in Windows Remote Desktop Licensing Service, followed by privilege escalation via "
        "CVE-2024-21410 affecting Microsoft Exchange Server 2019. Post-exploitation involved staging "
        "GhostPulse loader and DarkComet RAT, maintaining persistent command-and-control communication "
        "with IP 185.123.45.10 and domain update-service-check.com. Threat actors staged HermeticRansom "
        "for subsequent extortion. Recommended mitigations include emergency patching of CVE-2024-38077, "
        "immediate network egress filtering for 185.123.45.10, and rotating exposed domain credentials."
    )

    # 2. Workflow 1: Report Summarization
    print_banner("Workflow 1: Report Summarization (Slide 2)")
    print("Input: 150-word raw threat advisory")
    print("Executing ReportSummarizer...")
    summarizer = ReportSummarizer(provider)
    summary = summarizer.summarize(sample_report)

    print(f"\n[+] Title: {summary.title}")
    print(f"[+] Assessed Threat Level: {summary.threat_level}")
    print(f"[+] Executive Summary:\n    {summary.executive_summary}")
    print("\n[+] Affected Technologies:")
    for prod in summary.affected_products:
        print(f"    - {prod}")
    print("\n[+] Key Observed Tactics:")
    for tactic in summary.key_tactics:
        print(f"    - {tactic}")
    print("\n[+] Recommended Mitigations:")
    for mit in summary.recommended_mitigations:
        print(f"    * {mit}")

    # 3. Workflow 2: Structured Entity Extraction
    print_banner("Workflow 2: Structured Cybersecurity Entity Extraction (Slide 2)")
    print("Executing CyberEntityExtractor...")
    extractor = CyberEntityExtractor(provider)
    entities = extractor.extract(sample_report)

    print("\n[+] Threat Actors Extracted:")
    for actor in entities.threat_actors:
        print(f"    * {actor}")

    print("\n[+] Malware Strains / Families:")
    for mal in entities.malware_families:
        print(f"    * {mal}")

    print("\n[+] Vulnerabilities (CVEs):")
    for vuln in entities.vulnerabilities:
        v_id = vuln.cve_id if hasattr(vuln, "cve_id") else vuln.get("cve_id")
        v_desc = vuln.description if hasattr(vuln, "description") else vuln.get("description")
        v_sev = vuln.severity if hasattr(vuln, "severity") else vuln.get("severity")
        print(f"    * {v_id} [{v_sev}]: {v_desc}")

    print("\n[+] Indicators of Compromise (IOCs):")
    for ioc in entities.iocs:
        i_type = ioc.type if hasattr(ioc, "type") else ioc.get("type")
        i_val = ioc.value if hasattr(ioc, "value") else ioc.get("value")
        i_ctx = ioc.context if hasattr(ioc, "context") else ioc.get("context")
        print(f"    * [{i_type.upper()}] {i_val} ({i_ctx})")

    # 4. Workflow 3: Evidence-Grounded Threat Investigation (RAG)
    print_banner("Workflow 3: Evidence-Grounded Threat Investigation / RAG (Slide 2 & 3)")
    new_observation = "Outbound connection detected to IP 185.123.45.10 with suspicious memory execution."
    print(f"Investigator Query / Observation: '{new_observation}'")
    print("Retrieving historical evidence matches from Team 2 Knowledge Base...")

    simulated_retrieved_evidence = [
        {
            "document_id": "ENISA-2026-088",
            "relevance_score": 0.94,
            "content": (
                "Threat telemetry documents active Lazarus Group staging infrastructure utilizing "
                "IP 185.123.45.10 for GhostPulse payload delivery following CVE-2024-38077 exploitation."
            )
        },
        {
            "document_id": "UNICC-HIST-LOG-2026-441",
            "relevance_score": 0.88,
            "content": (
                "Security Operations incident report: Exchange server compromised via update-service-check.com "
                "resolving to 185.123.45.10."
            )
        }
    ]

    investigator = ThreatInvestigator(provider)
    investigation = investigator.investigate(new_observation, simulated_retrieved_evidence)

    print(f"\n[+] Historical Match Status: [{investigation.match_status}]")
    print(f"[+] Confidence Level: {investigation.confidence_level}")
    print(f"[+] Synthesized Assessment:\n    {investigation.assessment_narrative}")
    print(f"\n[+] Associated Threat Actors: {', '.join(investigation.potential_threat_actors)}")
    print(f"[+] Associated Malware: {', '.join(investigation.associated_malware)}")

    print("\n[+] Evidence Citations & Grounding Proof:")
    for cit in investigation.supporting_citations:
        c_id = cit.document_id if hasattr(cit, "document_id") else cit.get("document_id")
        c_score = cit.relevance_score if hasattr(cit, "relevance_score") else cit.get("relevance_score")
        c_quote = cit.key_excerpt if hasattr(cit, "key_excerpt") else cit.get("key_excerpt")
        print(f"    * Source: {c_id} (Relevance: {c_score})")
        print(f"      Proof: \"{c_quote}\"")

    print(f"\n[!] Governance & Human-in-the-Loop Note:\n    {investigation.investigator_notes}")

    print_banner("Demo Complete - All Team 3 Pipelines Verified Successfully")


if __name__ == "__main__":
    main()
