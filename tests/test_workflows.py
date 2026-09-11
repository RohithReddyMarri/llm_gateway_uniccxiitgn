"""
Automated unit tests for Team 3: LLM Gateway, Schemas, and Workflows.
Can be executed via standard python unittest or pytest:
    python -m unittest discover tests
"""

import unittest
import os
import sys

# Ensure root directory is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from llm.gateway.factory import get_llm_provider
from llm.schemas.report_summary import ThreatReportSummary
from llm.schemas.cyber_entities import ExtractedCyberEntities, VulnerabilityReference, IndicatorOfCompromise
from llm.schemas.investigation import InvestigationResult
from llm.workflows.summarizer import ReportSummarizer
from llm.workflows.extractor import CyberEntityExtractor
from llm.workflows.investigator import ThreatInvestigator
from evaluation.metrics import calculate_prf1, calculate_groundedness_score


class TestTeam3Workflows(unittest.TestCase):

    def setUp(self):
        self.provider = get_llm_provider(backend="mock")
        self.sample_text = (
            "In August 2026, Lazarus Group exploited CVE-2024-38077 and deployed GhostPulse. "
            "C2 node identified at 185.123.45.10."
        )

    def test_mock_gateway_instantiation(self):
        """Verify model-agnostic gateway factory correctly instantiates Mock provider."""
        self.assertIsNotNone(self.provider)
        self.assertEqual(self.provider.model_name, "mock-cyber-v1")

    def test_report_summarizer_workflow(self):
        """Verify Workflow 1 produces valid ThreatReportSummary."""
        summarizer = ReportSummarizer(self.provider)
        summary = summarizer.summarize(self.sample_text)
        self.assertIsInstance(summary, ThreatReportSummary)
        self.assertTrue(len(summary.title) > 0)
        self.assertIn(summary.threat_level, ["Critical", "High", "Medium", "Low", "Informational"])

    def test_entity_extractor_workflow(self):
        """Verify Workflow 2 extracts structured CVEs, IOCs, and malware."""
        extractor = CyberEntityExtractor(self.provider)
        entities = extractor.extract(self.sample_text)
        self.assertIsInstance(entities, ExtractedCyberEntities)
        self.assertTrue(len(entities.threat_actors) > 0)
        self.assertTrue(len(entities.vulnerabilities) > 0)
        self.assertTrue(len(entities.iocs) > 0)

    def test_threat_investigator_workflow(self):
        """Verify Workflow 3 produces grounded investigation with citations."""
        investigator = ThreatInvestigator(self.provider)
        evidence = [
            {
                "document_id": "ENISA-2026-088",
                "relevance_score": 0.94,
                "content": "C2 node 185.123.45.10 observed receiving telemetry from GhostPulse loader."
            }
        ]
        result = investigator.investigate(
            observation="Observed traffic to 185.123.45.10",
            retrieved_evidence=evidence
        )
        self.assertIsInstance(result, InvestigationResult)
        self.assertIn(result.match_status, ["Exact", "Strong", "Partial", "Weak", "Unsupported"])
        self.assertTrue(len(result.supporting_citations) > 0)
        self.assertEqual(result.supporting_citations[0].document_id, "ENISA-2026-088")

    def test_precision_recall_f1_metric(self):
        """Verify evaluation metrics calculation."""
        pred = {"CVE-2024-38077", "CVE-2024-21410"}
        gt = {"CVE-2024-38077", "CVE-2024-21410"}
        res = calculate_prf1(pred, gt)
        self.assertEqual(res["precision"], 1.0)
        self.assertEqual(res["recall"], 1.0)
        self.assertEqual(res["f1"], 1.0)

    def test_groundedness_score_calculation(self):
        """Verify groundedness citation verification."""
        citations = [{"document_id": "DOC-1"}, {"document_id": "DOC-2"}]
        provided = {"DOC-1", "DOC-2", "DOC-3"}
        res = calculate_groundedness_score(citations, provided)
        self.assertEqual(res["groundedness_score"], 1.0)
        self.assertEqual(res["verified_citations"], 2)

    def test_top_level_sdk_helpers_for_team4(self):
        """Verify 1-line integration helper functions return valid dicts directly."""
        from llm import summarize_report, extract_entities, investigate_threat

        summary_dict = summarize_report(self.sample_text, backend="mock")
        self.assertIsInstance(summary_dict, dict)
        self.assertIn("executive_summary", summary_dict)

        entities_dict = extract_entities(self.sample_text, backend="mock")
        self.assertIsInstance(entities_dict, dict)
        self.assertIn("vulnerabilities", entities_dict)

        evidence = [{"document_id": "ENISA-2026-088", "relevance_score": 0.94, "content": "Proof"}]
        inv_dict = investigate_threat("Observed threat", evidence, backend="mock")
        self.assertIsInstance(inv_dict, dict)
        self.assertIn("match_status", inv_dict)


if __name__ == "__main__":
    unittest.main()

