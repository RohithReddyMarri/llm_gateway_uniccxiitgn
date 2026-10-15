"""
Evaluation Metrics Engine for Team 3 (LLM Intelligence & Evaluation).
Implements mathematical scoring for:
1. Entity Extraction (Precision, Recall, F1, Macro F1 across CVE, IOC, Malware, Actor)
2. Evidence Groundedness (Citation verification, Hallucination detection)
3. Patch & Remediation Extraction (Task 3.0: Status, Affected/Fixed Versions, Workarounds)
4. Workflow Latency SLA
"""

from typing import Set, Dict, Any, List, Optional


def calculate_prf1(predicted: Set[str], ground_truth: Set[str]) -> Dict[str, float]:
    """Calculates standard Precision, Recall, and F1 score between two sets of strings."""
    pred_clean = {p.strip().lower() for p in predicted if p and isinstance(p, str) and p.strip()}
    gt_clean = {g.strip().lower() for g in ground_truth if g and isinstance(g, str) and g.strip()}

    if not gt_clean and not pred_clean:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0, "tp": 0, "fp": 0, "fn": 0}
    if not pred_clean or not gt_clean:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "tp": 0, "fp": len(pred_clean), "fn": len(gt_clean)}

    true_positives = len(pred_clean.intersection(gt_clean))
    false_positives = len(pred_clean - gt_clean)
    false_negatives = len(gt_clean - pred_clean)

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "tp": true_positives,
        "fp": false_positives,
        "fn": false_negatives,
    }


def calculate_extraction_metrics(
    extracted: Dict[str, Any],
    ground_truth: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Evaluates entity-level extraction across CVEs, IOCs, Malware, and Threat Actors.
    """
    # Extract predicted sets
    pred_cves = {
        v.get("cve_id", "") if isinstance(v, dict) else getattr(v, "cve_id", "")
        for v in extracted.get("vulnerabilities", [])
    }
    pred_iocs = {
        i.get("value", "") if isinstance(i, dict) else getattr(i, "value", "")
        for i in extracted.get("iocs", [])
    }
    pred_malware = set(extracted.get("malware_families", []))
    pred_actors = set(extracted.get("threat_actors", []))

    # Evaluate each dimension
    cve_metrics = calculate_prf1(pred_cves, set(ground_truth.get("cves", [])))
    ioc_metrics = calculate_prf1(pred_iocs, set(ground_truth.get("iocs", [])))
    malware_metrics = calculate_prf1(pred_malware, set(ground_truth.get("malware_families", [])))
    actor_metrics = calculate_prf1(pred_actors, set(ground_truth.get("threat_actors", [])))

    # Compute macro-average F1 across all 4 entity dimensions
    macro_f1 = round((cve_metrics["f1"] + ioc_metrics["f1"] + malware_metrics["f1"] + actor_metrics["f1"]) / 4.0, 3)

    return {
        "macro_f1": macro_f1,
        "cve": cve_metrics,
        "ioc": ioc_metrics,
        "malware": malware_metrics,
        "threat_actor": actor_metrics,
    }


def calculate_groundedness_score(
    citations: List[Any],
    provided_evidence_ids: Set[str]
) -> Dict[str, Any]:
    """
    Evaluates evidence groundedness:
    Verifies that claims cite actual provided documents without hallucinated citations.
    """
    if not citations:
        return {
            "groundedness_score": 0.0,
            "total_citations": 0,
            "verified_citations": 0,
            "hallucinated_citations": 0
        }

    total = len(citations)
    verified = 0

    for cit in citations:
        doc_id = cit.get("document_id") if isinstance(cit, dict) else getattr(cit, "document_id", "")
        if doc_id in provided_evidence_ids:
            verified += 1

    score = round(verified / total, 3) if total > 0 else 0.0
    return {
        "groundedness_score": score,
        "total_citations": total,
        "verified_citations": verified,
        "hallucinated_citations": total - verified,
    }


def calculate_patch_metrics(
    extracted_patch: Dict[str, Any],
    ground_truth_patch: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Evaluates Task 3.0 (Patch Identification) against UNICC Evaluation Criteria:
    - Measures categorical clarity (patch_status: 'Available' | 'No Official Patch' | 'Workaround Only' | 'Not Applicable')
    - Measures precision in affected versions, fixed versions, and remediation workarounds.
    Target SLA: >= 80% precision.
    """
    if not extracted_patch:
        extracted_patch = {}
    if not ground_truth_patch:
        ground_truth_patch = {}

    pred_status = str(extracted_patch.get("patch_status", "Unknown")).strip().lower()
    gt_status = str(ground_truth_patch.get("patch_status", "Unknown")).strip().lower()

    status_match = (pred_status == gt_status) if gt_status != "unknown" else False

    pred_affected = set(extracted_patch.get("affected_versions", []))
    gt_affected = set(ground_truth_patch.get("affected_versions", []))
    affected_metrics = calculate_prf1(pred_affected, gt_affected)

    pred_fixed = set(extracted_patch.get("fixed_versions", []))
    gt_fixed = set(ground_truth_patch.get("fixed_versions", []))
    fixed_metrics = calculate_prf1(pred_fixed, gt_fixed)

    pred_workarounds = set(extracted_patch.get("remediation_workarounds", []))
    gt_workarounds = set(ground_truth_patch.get("remediation_workarounds", []))
    workaround_metrics = calculate_prf1(pred_workarounds, gt_workarounds)

    # Composite precision score for patch identification:
    # 40% status categorical accuracy + 30% affected versions precision + 30% fixed versions precision
    status_score = 1.0 if status_match else 0.0
    composite_precision = round(
        (status_score * 0.40) +
        (affected_metrics["precision"] * 0.30) +
        (fixed_metrics["precision"] * 0.30),
        3
    )

    return {
        "status_match": status_match,
        "predicted_status": extracted_patch.get("patch_status", "Unknown"),
        "ground_truth_status": ground_truth_patch.get("patch_status", "Unknown"),
        "composite_precision": composite_precision,
        "affected_versions": affected_metrics,
        "fixed_versions": fixed_metrics,
        "remediation_workarounds": workaround_metrics,
    }
