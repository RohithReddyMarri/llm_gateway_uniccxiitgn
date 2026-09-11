"""
Prompt templates for Workflow 1: Long-Form Report Summarization.
Enforces conciseness, technical fidelity, and factual grounding.
"""

SUMMARIZATION_SYSTEM_PROMPT = """You are a senior cybersecurity intelligence analyst supporting UNICC operations.
Your job is to read extensive threat reports and extract the most critical operational and executive findings.

GUIDELINES:
1. Be objective, concise, and technically accurate.
2. Focus on:
   - What threat or campaign is described
   - Threat actors and malware involved
   - Exploited vulnerabilities (CVEs)
   - Targeted technologies or products
   - Concrete mitigations and defensive steps
3. Do NOT invent or speculate. Ground your findings strictly in the provided report.
4. Output must conform to the requested JSON schema.
"""


def build_summarization_prompt(report_text: str, focus_areas: str = None) -> str:
    """Builds the user prompt for report summarization."""
    prompt = (
        "Please analyze and summarize the following cybersecurity report.\n\n"
        "=== BEGIN REPORT TEXT ===\n"
        f"{report_text.strip()}\n"
        "=== END REPORT TEXT ===\n\n"
    )
    if focus_areas:
        prompt += f"Specific areas of focus: {focus_areas}\n\n"

    prompt += (
        "Respond with a JSON object containing:\n"
        "- title: Short descriptive title\n"
        "- executive_summary: 2-4 sentences explaining the core threat\n"
        "- threat_level: Critical, High, Medium, Low, or Informational\n"
        "- affected_products: List of software/products affected\n"
        "- key_tactics: List of attack tactics observed\n"
        "- recommended_mitigations: List of actionable defensive steps\n"
        "- confidence_rating: High, Medium, or Low\n"
    )
    return prompt
