# 📊 LLM Intelligence & Evaluation Benchmark Suite

Official evaluation subsystem for the LLM Intelligence Layer of the **UNICC × IITGN Cybersecurity Capstone**.

## 📊 Overview

The evaluation framework quantitatively assesses the cognitive and generative layer across five core pillars:
1. **Cyber Entity Extraction Fidelity**:
   - `Macro F1`: Unweighted mean F1 score across 4 key entity classes: CVE vulnerabilities, IOCs (IPs, domains), Malware Families, and Threat Actors.
   - Per-class Precision, Recall, and F1.
2. **Evidence Groundedness & Anti-Hallucination (RAG)**:
   - `Groundedness Score`: Ratio of model citations that strictly match provided retrieved intelligence records vs. hallucinated document references.
   - `Hallucination Rate`: $1.0 - \text{Groundedness Score}$.
3. **Patch & Remediation Intelligence Precision**:
   - Evaluates categorical clarity (`'Available'`, `'No Official Patch'`, `'Workaround Only'`, `'Not Applicable'`).
   - Evaluates precision in affected software versions, official fixed releases/bulletins (e.g. `MS17-010`), and actionable remediation workarounds.
   - Target SLA: $\ge 80\%$ precision.
4. **Threat Report Summarization Quality**:
   - Factuality, completeness, and key indicator retention.
5. **Inference Latency SLA**:
   - Tracks per-workflow and total end-to-end reasoning time for local on-premise execution (Ollama) and cloud APIs.

---

## 📁 Directory Structure

```text
llm/evaluation/
├── __init__.py               # Package exports
├── metrics.py                # Mathematical scoring engine (Precision, Recall, F1, Groundedness, Patch Precision)
├── benchmark_data.py         # Calibrated ground-truth CTI scenarios and answer keys
├── evaluate_llm.py           # Official benchmark execution runner and scorecard generator
├── benchmark_results.json    # Structured evaluation output and per-scenario trace
└── README.md                 # Subsystem documentation
```

---

## 🚀 Running the Benchmarks

### 1. Default Run (Local Ollama on-premise)
Run the automated evaluation against the ground-truth benchmark suite:
```bash
python llm/evaluation/evaluate_llm.py
```
Or via module invocation:
```bash
python -m llm.evaluation.evaluate_llm
```

### 2. Evaluating Cloud/API Provider
```bash
python llm/evaluation/evaluate_llm.py --backend=api
```

### 3. Custom Output Destination
```bash
python llm/evaluation/evaluate_llm.py --output=llm/evaluation/custom_results.json
```

---

## 🎯 Quality Gates

| Gate | Target SLA | Metric |
| :--- | :--- | :--- |
| **Extraction Gate** | `PASS` ($\ge 80\%$) | Macro F1 across CVEs, IOCs, Malware, and Threat Actors |
| **Groundedness Gate**| `PASS` ($\ge 90\%$) | Citation verification ratio ($\le 10\%$ hallucination) |
| **Patch Intelligence Gate** | `PASS` ($\ge 80\%$) | Patch status accuracy & affected/fixed version precision |
| **Latency SLA** | Informational | Average seconds per end-to-end investigation workflow |

---

## 📈 Benchmark Performance Results

| Evaluation Dimension | Metric Score | Target Gate | Status |
| :--- | :--- | :--- | :--- |
| **Entity Extraction Macro F1** | **82.3%** | $\ge 80\%$ | `PASS` |
| • *CVE Identifiers* | 100.0% | — | Full exact precision |
| • *Technical IOCs (IP/Domain/Hash)* | 83.3% | — | TLD & noise filtered |
| • *Malware Families* | 90.0% | — | Canonical resolution |
| • *Threat Actors* | 50.0% | — | Alias matching |
| **Evidence Groundedness (RAG)** | **100.0%** | $\ge 90\%$ | `PASS` |
| **Hallucination Rate** | **0.0%** | $\le 10\%$ | `PASS` |
| **End-to-End Latency SLA (Cloud)** | **~1.4s** | Informational | Sub-2s SLA |
| **End-to-End Latency SLA (Local)** | **~163s** | Informational | CPU on-premise execution |
