# UNICC × IITGN Capstone Project — AI & Cybersecurity
## Team 3: LLM Intelligence & Evaluation Layer

### Team Members
- **Rohith Reddy Marri** (Roll No: 24110303) — `rohith.marri@iitgn.ac.in`
- **Vallapudasu Hanook** (Roll No: 24110378) — `vallapudasu.hanook@iitgn.ac.in`

---

## What is This Project?

When cybersecurity investigators at the United Nations (UNICC) analyze a suspicious alert or a new attack, they often face hundreds of pages of past incident reports, vulnerability databases, and security logs. Reading all of that manually takes hours.

**Team 3 builds the AI reasoning engine (LLM layer)** that helps investigators do this in seconds:
1. **Summarize** long threat reports into quick, readable executive overviews.
2. **Extract** technical details (like CVE vulnerability IDs, suspicious IPs, malware names, and hacker groups) into clean, organized data.
3. **Investigate & Correlate (RAG):** Check whether a newly observed threat matches any historical incidents in the UNICC knowledge base, citing the exact source documents so the AI never makes things up.

---

## How the 4 Teams Work Together

Our project is divided across 4 student teams working like a relay race:

```
[Team 1: Data Preparation]
  Downloads and cleans raw reports from ENISA, NIST, CVE, and Shadowserver.
       │
       ▼
[Team 2: Search & Retrieval]
  Stores cleaned reports in a database and searches for matches when a query comes in.
       │
       ▼ (Passes relevant evidence documents)
[TEAM 3: LLM Intelligence Layer]  ◄── THIS REPOSITORY (Rohith & Hanook)
  • Routes to Local (on-premise) or Cloud AI models via a unified Gateway.
  • Summarizes, extracts entities, and synthesizes grounded investigation reports.
  • Validates outputs to prevent hallucinations and enforces strict JSON formats.
  • Evaluates accuracy, precision/recall, and grounding scores.
       │
       ▼ (Hands over clean JSON)
[Team 4: Application Dashboard]
  Builds the web UI where human investigators review findings and take action.
```

---

## Core Components

### 1. Model-Agnostic Gateway (`llm/gateway/`)
* **Why it matters:** UNICC handles sensitive cyber data. In real-world deployment, they want the AI to run **locally and privately** (using Ollama / Llama-3) so no data leaves the UN network. But during development, we also want to test with **Cloud APIs** (like OpenAI or Gemini).
* **What we built:** A simple adapter system where you can switch models with just one word (`backend="local"`, `"api"`, or `"mock"`).
* **Offline Mock Provider:** Includes a built-in mock mode that runs immediately on any computer with **zero setup, zero API keys, and no GPU required**.

### 2. The 3 Core Workflows (`llm/workflows/`)
* **Workflow 1: Report Summarizer (`summarizer.py`)**  
  Turns long, multi-page security advisories into clean summaries covering the threat level, affected software, and immediate mitigations.
* **Workflow 2: Entity Extractor (`extractor.py`)**  
  Scans unstructured text and extracts structured indicators (CVEs, IP addresses, domains, file hashes, malware strains) compatible with UNICC feeds like **Abuse.ch ThreatFox** and **Shadowserver**.
* **Workflow 3: Evidence-Grounded Investigator (`investigator.py`)**  
  Takes a new threat query + historical evidence from Team 2 and writes an investigation assessment. It requires the AI to **cite the exact document ID and quote** for every claim to prevent hallucinations.

### 3. Evaluation & Benchmarking (`evaluation/`)
* **Why it matters:** We don't just guess if our AI is good; we measure it mathematically.
* **What we built:** An automated benchmark runner that tests our system against realistic threat cases and measures:
  * **Entity Extraction F1 Score:** Did the AI extract the right CVEs and IPs?
  * **Evidence Grounding Rate:** Did the AI cite real documents or make things up?
  * **Latency:** How fast does each workflow respond?

---

## Quick Start (Run It on Your Machine)

### Requirements
- Python 3.9 or newer.
- Install dependencies (optional for mock mode, standard libraries are supported):
  ```bash
  pip install -r requirements.txt
  ```

---

### Option 1: Run the Interactive Demo
See all 3 workflows run end-to-end right in your terminal:

```bash
python run_team3_demo.py
```
*(By default, this runs in offline mock mode so you can test it instantly without any API keys).*

To run with a local Ollama model (e.g., Llama-3):
```bash
python run_team3_demo.py --backend local --model llama3:8b
```

To run with a cloud API:
```bash
set LLM_API_KEY=your_key_here
python run_team3_demo.py --backend api --model gpt-4o-mini
```

---

### Option 2: Run the Evaluation Benchmark
Run our benchmark suite to calculate Precision, Recall, F1, and Grounding scores:

```bash
python evaluation/evaluate_team3.py
```

---

### Option 3: Run Automated Unit Tests
Run our test suite to verify all schemas, gateway adapters, and workflows:

```bash
python -m unittest discover tests
```

---

## 1-Line Integration for Team 4 (Dashboard Team)

Team 4 can import and use our pipelines in their backend with just **one line of code**:

```python
from llm import summarize_report, extract_entities, investigate_threat

# 1. Summarize a report -> returns clean JSON dictionary
summary = summarize_report(raw_report_text)

# 2. Extract CVEs and IOCs -> returns clean JSON dictionary
entities = extract_entities(raw_log_text)

# 3. Investigate a new threat -> returns citation-backed JSON dictionary
investigation = investigate_threat(
    observation="Suspicious connection to IP 185.123.45.10",
    retrieved_evidence=team2_search_results
)
```

---

## Project Structure

```
unicc-cyber-ai/
├── README.md                        # Project documentation (this file)
├── requirements.txt                 # Python dependencies
├── .gitignore                       # Clean Git configuration
├── run_team3_demo.py                # Live interactive demo script
├── llm/
│   ├── __init__.py                  # 1-line SDK functions for Team 4
│   ├── gateway/                     # Model-Agnostic LLM Gateway
│   │   ├── interface.py             # Common provider blueprint & JSON cleaner
│   │   ├── mock_provider.py         # Instant offline provider
│   │   ├── factory.py               # Model switcher (mock, local, api)
│   │   ├── local/ollama_provider.py # Local Ollama adapter
│   │   └── api/api_provider.py      # Cloud API adapter
│   ├── schemas/                     # Strict JSON data structures
│   │   ├── report_summary.py        # Summary schema
│   │   ├── cyber_entities.py        # CVEs, IOCs, Malware schema
│   │   └── investigation.py         # Grounded investigation schema
│   ├── prompts/                     # System prompt templates & anti-hallucination rules
│   │   ├── summarization_prompts.py
│   │   ├── extraction_prompts.py
│   │   └── investigation_prompts.py
│   └── workflows/                   # Core pipeline logic
│       ├── summarizer.py            # Workflow 1 implementation
│       ├── extractor.py             # Workflow 2 implementation
│       └── investigator.py          # Workflow 3 implementation
├── evaluation/                      # Slide 3 Evaluation Benchmark
│   ├── benchmark_data.py            # Real threat test cases (Lazarus, LockBit, ThreatFox)
│   ├── metrics.py                   # Precision, Recall, F1 & Groundedness math
│   └── evaluate_team3.py            # Automated scorecard runner
└── tests/
    └── test_workflows.py            # Automated unit tests
```
