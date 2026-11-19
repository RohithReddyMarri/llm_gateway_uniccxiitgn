"""
Evaluation Metrics Engine for LLM Intelligence & Evaluation.
Implements mathematical scoring for:
1. Entity Extraction (Precision, Recall, F1, Macro F1 across CVE, IOC, Malware, Actor)
2. Evidence Groundedness (Citation verification, Hallucination detection)
3. Patch & Remediation Extraction (Status, Affected/Fixed Versions, Workarounds)
4. Workflow Latency SLA
"""

import re
from typing import Set, Dict, Any, List, Optional


def calculate_prf1(predicted: Set[str], ground_truth: Set[str], relaxed: bool = True) -> Dict[str, float]:
    """
    Calculates Precision, Recall, and F1 score between two sets of strings.
    Supports relaxed substring/overlap matching for realistic natural language entities.
    Requires minimum length and token boundary to prevent single-character false matches.
    """
    pred_clean = {p.strip().lower() for p in predicted if p and isinstance(p, str) and p.strip()}
    gt_clean = {g.strip().lower() for g in ground_truth if g and isinstance(g, str) and g.strip()}

    if not gt_clean and not pred_clean:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0, "tp": 0, "fp": 0, "fn": 0}
    if not pred_clean or not gt_clean:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "tp": 0, "fp": len(pred_clean), "fn": len(gt_clean)}

    matched_gt = set()
    matched_pred = set()

    for p in pred_clean:
        for g in gt_clean:
            if g in matched_gt:
                continue
            match = False
            if p == g:
                match = True
            elif relaxed:
                min_len = min(len(p), len(g))
                # Require at least 3 characters for substring matching to avoid single/double char false positives
                if min_len >= 3 and (p in g or g in p):
                    match = True
                else:
                    # Check token overlap for multi-word entities (e.g. "lazarus" in "lazarus group")
                    p_words = {w for w in re.findall(r"\w+", p) if len(w) >= 3}
                    g_words = {w for w in re.findall(r"\w+", g) if len(w) >= 3}
                    if p_words and g_words and len(p_words & g_words) > 0:
                        match = True

            if match:
                matched_gt.add(g)
                matched_pred.add(p)
                break

    true_positives = len(matched_pred)
    false_positives = len(pred_clean - matched_pred)
    false_negatives = len(gt_clean - matched_gt)

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
    Evaluates extraction fidelity across 4 primary cyber classes:
    - CVE Identifiers
    - Technical IOCs (IPs, Domains, Hashes)
    - Malware Families
    - Threat Actors
    """
    # 1. CVEs
    pred_cves = {
        v.get("cve_id", "").upper() if isinstance(v, dict) else getattr(v, "cve_id", "").upper()
        for v in extracted.get("vulnerabilities", [])
    }
    gt_cves = {c.upper() for c in ground_truth.get("cves", [])}
    cve_metrics = calculate_prf1(pred_cves, gt_cves, relaxed=False)

    # 2. IOCs
    pred_iocs = {
        i.get("value", "").lower() if isinstance(i, dict) else getattr(i, "value", "").lower()
        for i in extracted.get("iocs", [])
    }
    gt_iocs = {i.lower() for i in ground_truth.get("iocs", [])}
    ioc_metrics = calculate_prf1(pred_iocs, gt_iocs, relaxed=True)

    # 3. Malware
    pred_malware = set(extracted.get("malware_families", []))
    gt_malware = set(ground_truth.get("malware_families", []))
    malware_metrics = calculate_prf1(pred_malware, gt_malware, relaxed=True)

    # 4. Threat Actors
    pred_actors = set(extracted.get("threat_actors", []))
    gt_actors = set(ground_truth.get("threat_actors", []))
    actor_metrics = calculate_prf1(pred_actors, gt_actors, relaxed=True)

    macro_f1 = round((cve_metrics["f1"] + ioc_metrics["f1"] + malware_metrics["f1"] + actor_metrics["f1"]) / 4.0, 3)

    return {
        "macro_f1": macro_f1,
        "cve": cve_metrics,
        "ioc": ioc_metrics,
        "malware": malware_metrics,
        "actor": actor_metrics,
    }


def calculate_groundedness_score(
    citations: List[Any],
    provided_evidence_ids: List[str]
) -> Dict[str, Any]:
    """
    Evaluates evidence groundedness:
    Verifies that claims cite actual provided documents without hallucinated citations.
    """
    clean_provided = {pid.strip().lower() for pid in provided_evidence_ids if pid and pid.strip()}

    # If no evidence was provided (e.g. unsupported scenario), and model produced no citations,
    # the model behaved correctly with 0 hallucinations.
    if not clean_provided:
        if not citations:
            return {
                "groundedness_score": 1.0,
                "total_citations": 0,
                "verified_citations": 0,
                "hallucinated_citations": 0
            }
        else:
            return {
                "groundedness_score": 0.0,
                "total_citations": len(citations),
                "verified_citations": 0,
                "hallucinated_citations": len(citations)
            }

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
        clean_doc = (doc_id or "").strip().lower()
        if not clean_doc or len(clean_doc) < 3:
            continue

        is_verified = False
        for pid in clean_provided:
            if clean_doc == pid:
                is_verified = True
                break
            if len(clean_doc) >= 4 and len(pid) >= 4:
                if clean_doc in pid or pid in clean_doc:
                    is_verified = True
                    break
        if is_verified:
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
    Evaluates Patch Identification & Remediation Precision:
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

    if pred_status == gt_status:
        status_match = True
    elif ("available" in pred_status and "available" in gt_status) or ("no" in pred_status and "no" in gt_status):
        status_match = True
    else:
        status_match = False

    pred_affected = set(extracted_patch.get("affected_versions", []))
    gt_affected = set(ground_truth_patch.get("affected_versions", []))
    affected_metrics = calculate_prf1(pred_affected, gt_affected)

    pred_fixed = set(extracted_patch.get("fixed_versions", []))
    gt_fixed = set(ground_truth_patch.get("fixed_versions", []))
    fixed_metrics = calculate_prf1(pred_fixed, gt_fixed)

    pred_workarounds = set(extracted_patch.get("remediation_workarounds", []))
    gt_workarounds = set(ground_truth_patch.get("remediation_workarounds", []))
    workaround_metrics = calculate_prf1(pred_workarounds, gt_workarounds)

    status_score = 1.0 if status_match else 0.0
    composite_precision = round(
        (status_score * 0.30) +
        (affected_metrics["precision"] * 0.25) +
        (fixed_metrics["precision"] * 0.25) +
        (workaround_metrics["precision"] * 0.20),
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
