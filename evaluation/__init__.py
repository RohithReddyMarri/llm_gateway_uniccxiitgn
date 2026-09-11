"""Evaluation and benchmarking framework for Team 3."""
from .metrics import calculate_extraction_metrics, calculate_groundedness_score
from .benchmark_data import BENCHMARK_CASES

__all__ = ["calculate_extraction_metrics", "calculate_groundedness_score", "BENCHMARK_CASES"]
