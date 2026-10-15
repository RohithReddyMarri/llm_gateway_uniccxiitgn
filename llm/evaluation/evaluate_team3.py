#!/usr/bin/env python3
"""
llm/evaluation/evaluate_team3.py
================================
Official Benchmark Evaluation Suite for Team 3 (LLM Intelligence & Evaluation).

Evaluates:
1. Cyber Entity Extraction (Macro F1 across CVEs, IOCs, Malware Families, Threat Actors)
2. Evidence Groundedness (RAG citation fidelity and hallucination detection)
3. Patch & Remediation Intelligence (Task 3.0: status clarity, affected/fixed versions, workarounds)
4. Workflow Latency SLA across Local (Ollama on-premise) and Cloud/API backends.

Usage:
    python llm/evaluation/evaluate_team3.py
    python llm/evaluation/evaluate_team3.py --backend=local
    python llm/evaluation/evaluate_team3.py --backend=api
    python llm/evaluation/evaluate_team3.py --output=llm/evaluation/benchmark_results.json
"""

import sys
import os
import time
import json
import argparse
from pathlib import Path
from datetime import datetime, timezone

# Ensure project root is in sys.path
_EVAL_DIR = Path(__file__).resolve().parent
_LLM_DIR = _EVAL_DIR.parent
_REPO_ROOT = _LLM_DIR.parent

for p in [_REPO_ROOT, _LLM_DIR, _EVAL_DIR]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from llm.gateway.factory import get_llm_provider
from llm.workflows.summarizer import ReportSummarizer
from llm.workflows.extractor import CyberEntityExtractor
from llm.workflows.investigator import ThreatInvestigator
from llm.evaluation.benchmark_data import BENCHMARK_CASES
from llm.evaluation.metrics import (
    calculate_extraction_metrics,
    calculate_groundedness_score,
    calculate_patch_metrics,
)

DEFAULT_OUTPUT = _EVAL_DIR / "benchmark_results.json"

# Quality Gate Thresholds
GATE_EXTRACTION_F1 = 0.80      # 80% Macro F1
GATE_GROUNDEDNESS = 0.90        # 90% Groundedness (max 10% hallucination)
GATE_PATCH_PRECISION = 0.80     # 80% Patch precision (UNICC Task 3.0 SLA)


def run_benchmark(backend: str = "local", output_file: str = None) -> dict:
    print("=" * 76)
    print(" UNICC x IITGN Capstone - Team 3 LLM Evaluation Benchmark Suite")
    print(f" Target Backend: {backend.upper()} | Model: Ollama / Configured Provider")
    print(f" Time: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 76)

    provider = get_llm_provider(backend=backend)
    summarizer = ReportSummarizer(provider)
    extractor = CyberEntityExtractor(provider)
    investigator = ThreatInvestigator(provider)

    total_cases = len(BENCHMARK_CASES)
    case_results = []

    macro_f1_scores = []
    groundedness_scores = []
    patch_scores = []
    latencies = []

    print(f"Loaded {total_cases} calibrated ground-truth benchmark scenarios.\n")

    for idx, case in enumerate(BENCHMARK_CASES, 1):
        case_id = case["case_id"]
        desc = case["description"]
        print(f"[{idx}/{total_cases}] Evaluating Scenario: {case_id}")
        print(f"       Description: {desc}")

        start_time = time.time()

        # 1. Summarization Workflow
        summary_result = summarizer.summarize(case["raw_text"])

        # 2. Structured Extraction Workflow
        extracted_entities = extractor.extract(case["raw_text"])
        ext_dict = extracted_entities.to_dict() if hasattr(extracted_entities, "to_dict") else extracted_entities
        ext_metrics = calculate_extraction_metrics(ext_dict, case["ground_truth_entities"])
        macro_f1_scores.append(ext_metrics["macro_f1"])

        # 3. Contextual Investigation Workflow (RAG Grounding & Task 3.0 Patch Evaluation)
        inv_result = investigator.investigate(
            observation=f"Investigate active threat report: {desc}",
            retrieved_evidence=case["retrieved_evidence"]
        )
        inv_dict = inv_result.to_dict() if hasattr(inv_result, "to_dict") else inv_result

        # Calculate Groundedness (Citations vs. Provided Documents)
        provided_ids = {d["document_id"] for d in case["retrieved_evidence"]}
        grounding = calculate_groundedness_score(inv_dict.get("supporting_citations", []), provided_ids)
        groundedness_scores.append(grounding["groundedness_score"])

        # Calculate Patch Identification Accuracy (Task 3.0)
        extracted_patch = inv_dict.get("patch_details", {})
        if hasattr(extracted_patch, "to_dict"):
            extracted_patch = extracted_patch.to_dict()
        patch_metrics = calculate_patch_metrics(extracted_patch, case.get("ground_truth_patch", {}))
        patch_scores.append(patch_metrics["composite_precision"])

        elapsed = time.time() - start_time
        latencies.append(elapsed)

        # Print per-case trace
        print(f"       -> Extraction Macro F1  : {ext_metrics['macro_f1'] * 100:.1f}% "
              f"(CVE: {ext_metrics['cve']['f1']*100:.0f}%, "
              f"IOC: {ext_metrics['ioc']['f1']*100:.0f}%, "
              f"Malware: {ext_metrics['malware']['f1']*100:.0f}%, "
              f"Actor: {ext_metrics['threat_actor']['f1']*100:.0f}%)")
        print(f"       -> Evidence Groundedness: {grounding['groundedness_score'] * 100:.1f}% "
              f"({grounding['verified_citations']}/{grounding['total_citations']} citations verified)")
        print(f"       -> Task 3.0 Patch Status: '{patch_metrics['predicted_status']}' "
              f"(Match GT: {patch_metrics['status_match']}, Composite Precision: {patch_metrics['composite_precision']*100:.1f}%)")
        print(f"       -> Latency: {elapsed:.2f}s\n")

        case_results.append({
            "case_id": case_id,
            "description": desc,
            "latency_seconds": round(elapsed, 2),
            "extraction_metrics": ext_metrics,
            "grounding_metrics": grounding,
            "patch_metrics": patch_metrics,
            "investigation_match_status": inv_dict.get("match_status"),
        })

    # Summary Statistics
    avg_f1 = sum(macro_f1_scores) / len(macro_f1_scores) if macro_f1_scores else 0.0
    avg_grounding = sum(groundedness_scores) / len(groundedness_scores) if groundedness_scores else 0.0
    avg_patch_precision = sum(patch_scores) / len(patch_scores) if patch_scores else 0.0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    hallucination_rate = 1.0 - avg_grounding

    gate_f1_pass = avg_f1 >= GATE_EXTRACTION_F1
    gate_grounding_pass = avg_grounding >= GATE_GROUNDEDNESS
    gate_patch_pass = avg_patch_precision >= GATE_PATCH_PRECISION

    summary = {
        "benchmark_timestamp": datetime.now(timezone.utc).isoformat(),
        "backend": backend,
        "total_cases_evaluated": total_cases,
        "metrics_summary": {
            "avg_extraction_macro_f1": round(avg_f1, 4),
            "avg_evidence_groundedness": round(avg_grounding, 4),
            "avg_hallucination_rate": round(hallucination_rate, 4),
            "avg_patch_precision": round(avg_patch_precision, 4),
            "avg_workflow_latency_seconds": round(avg_latency, 2),
        },
        "quality_gates": {
            "extraction_f1_gate": {"target": GATE_EXTRACTION_F1, "achieved": round(avg_f1, 4), "status": "PASS" if gate_f1_pass else "FAIL"},
            "groundedness_gate": {"target": GATE_GROUNDEDNESS, "achieved": round(avg_grounding, 4), "status": "PASS" if gate_grounding_pass else "FAIL"},
            "patch_precision_gate": {"target": GATE_PATCH_PRECISION, "achieved": round(avg_patch_precision, 4), "status": "PASS" if gate_patch_pass else "FAIL"},
        },
        "cases": case_results,
    }

    print("=" * 76)
    print(" SUMMARY BENCHMARK SCORECARD")
    print("=" * 76)
    print(f" Entity Extraction Macro F1   : {avg_f1 * 100:.2f}%  [{'PASS' if gate_f1_pass else 'FAIL'} - Gate >= {GATE_EXTRACTION_F1*100:.0f}%]")
    print(f" Evidence Groundedness        : {avg_grounding * 100:.2f}%  [{'PASS' if gate_grounding_pass else 'FAIL'} - Gate >= {GATE_GROUNDEDNESS*100:.0f}%]")
    print(f" Hallucination Rate           : {hallucination_rate * 100:.2f}%")
    print(f" Task 3.0 Patch Precision     : {avg_patch_precision * 100:.2f}%  [{'PASS' if gate_patch_pass else 'FAIL'} - Gate >= {GATE_PATCH_PRECISION*100:.0f}%]")
    print(f" Average Workflow Latency     : {avg_latency:.2f} seconds")
    print("=" * 76)

    # Save to JSON
    dest_path = Path(output_file) if output_file else DEFAULT_OUTPUT
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(dest_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"Saved benchmark results to: {dest_path}")

    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Team 3 LLM Evaluation Benchmark Suite")
    parser.add_argument("--backend", default="local", choices=["local", "api"], help="Target LLM backend (local: Ollama on-premise, api: cloud provider)")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Path to write structured JSON evaluation results")
    args = parser.parse_args()

    run_benchmark(backend=args.backend, output_file=args.output)
