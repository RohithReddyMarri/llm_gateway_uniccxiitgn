"""
Team 3 (LLM Intelligence & Evaluation) Benchmark Package.
Provides automated evaluation metrics, calibrated ground truth scenarios,
and execution runners for the LLM subsystem.
"""

from llm.evaluation.metrics import (
    calculate_prf1,
    calculate_extraction_metrics,
    calculate_groundedness_score,
    calculate_patch_metrics,
)
from llm.evaluation.benchmark_data import BENCHMARK_CASES
from llm.evaluation.evaluate_team3 import run_benchmark

__all__ = [
    "calculate_prf1",
    "calculate_extraction_metrics",
    "calculate_groundedness_score",
    "calculate_patch_metrics",
    "BENCHMARK_CASES",
    "run_benchmark",
]
