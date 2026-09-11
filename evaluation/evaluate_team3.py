"""
Evaluation Benchmark Runner for Team 3.
Executes automated benchmarks against test cases and outputs a comprehensive evaluation scorecard.
Usage:
    python evaluation/evaluate_team3.py --backend mock
    python evaluation/evaluate_team3.py --backend local
    python evaluation/evaluate_team3.py --backend api
"""

import sys
import os
import time
import argparse

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from llm.gateway.factory import get_llm_provider
from llm.workflows.summarizer import ReportSummarizer
from llm.workflows.extractor import CyberEntityExtractor
from llm.workflows.investigator import ThreatInvestigator
from evaluation.benchmark_data import BENCHMARK_CASES
from evaluation.metrics import calculate_extraction_metrics, calculate_groundedness_score


def run_benchmark(backend: str = "mock"):
    print("=" * 70)
    print(f" UNICC x IITGN Capstone - Team 3 LLM Evaluation Benchmark")
    print(f" Target Backend: {backend.upper()}")
    print("=" * 70)

    provider = get_llm_provider(backend=backend)
    summarizer = ReportSummarizer(provider)
    extractor = CyberEntityExtractor(provider)
    investigator = ThreatInvestigator(provider)

    total_cases = len(BENCHMARK_CASES)
    macro_f1_scores = []
    groundedness_scores = []
    latencies = []

    print(f"Loaded {total_cases} benchmark test cases.\n")

    for idx, case in enumerate(BENCHMARK_CASES, 1):
        case_id = case["case_id"]
        print(f"[{idx}/{total_cases}] Evaluating Case: {case_id} ({case['description']})")

        start_time = time.time()

        # 1. Test Summarization
        summary = summarizer.summarize(case["raw_text"])

        # 2. Test Extraction
        entities = extractor.extract(case["raw_text"])
        ext_dict = entities.to_dict() if hasattr(entities, "to_dict") else entities
        metrics = calculate_extraction_metrics(ext_dict, case["ground_truth_entities"])
        macro_f1_scores.append(metrics["macro_f1"])

        # 3. Test Investigation (RAG Grounding)
        inv_result = investigator.investigate(
            observation=f"Suspicious activity observed related to {case['description']}",
            retrieved_evidence=case["retrieved_evidence"]
        )
        inv_dict = inv_result.to_dict() if hasattr(inv_result, "to_dict") else inv_result
        provided_ids = {d["document_id"] for d in case["retrieved_evidence"]}
        grounding = calculate_groundedness_score(inv_dict.get("supporting_citations", []), provided_ids)
        groundedness_scores.append(grounding["groundedness_score"])

        elapsed = time.time() - start_time
        latencies.append(elapsed)

        print(f"  -> Extraction Macro F1: {metrics['macro_f1'] * 100:.1f}%")
        print(f"     * CVE F1: {metrics['cve']['f1'] * 100:.1f}%")
        print(f"     * IOC F1: {metrics['ioc']['f1'] * 100:.1f}%")
        print(f"     * Malware F1: {metrics['malware']['f1'] * 100:.1f}%")
        print(f"     * Threat Actor F1: {metrics['threat_actor']['f1'] * 100:.1f}%")
        print(f"  -> Evidence Groundedness: {grounding['groundedness_score'] * 100:.1f}% ({grounding['verified_citations']}/{grounding['total_citations']} citations verified)")
        print(f"  -> Latency: {elapsed:.2f}s\n")

    avg_f1 = sum(macro_f1_scores) / len(macro_f1_scores) if macro_f1_scores else 0.0
    avg_grounding = sum(groundedness_scores) / len(groundedness_scores) if groundedness_scores else 0.0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    print("=" * 70)
    print(" SUMMARY BENCHMARK SCORECARD")
    print("=" * 70)
    print(f" Overall Extraction Macro F1 : {avg_f1 * 100:.2f}%")
    print(f" Overall Evidence Grounding : {avg_grounding * 100:.2f}%")
    print(f" Average Workflow Latency   : {avg_latency:.2f} seconds")
    print(f" Hallucination Rate (Citations): {(1.0 - avg_grounding) * 100:.2f}%")
    print("=" * 70)
    print("Evaluation benchmark completed successfully.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Team 3 LLM Evaluation Benchmark")
    parser.add_argument("--backend", default="mock", choices=["mock", "local", "api"], help="LLM backend to evaluate")
    args = parser.parse_args()
    run_benchmark(backend=args.backend)
