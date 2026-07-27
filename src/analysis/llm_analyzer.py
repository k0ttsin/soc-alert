# analysis/llm_analyzer.py
from typing import List, Dict
import json

SYSTEM_PROMPT = """You are a Tier 1 SOC Analyst AI Assistant. Your job is to:
1. Analyze enriched security alerts
2. Provide clear, concise summaries for human analysts
3. Map observed behaviors to MITRE ATT&CK techniques with reasoning
4. Assign a priority score (1-10) and recommend immediate actions

Output FORMAT (JSON only):
{
  "summary": "2-3 sentence executive summary",
  "attack_narrative": "Step-by-step attack chain reconstruction",
  "mitre_mapping": [
    {"technique_id": "T1059.001", "tactic": "Execution", "confidence": 0.85, "evidence": "PowerShell encoded command observed in process command line"}
  ],
  "priority_score": 7,
  "recommended_actions": [
    "Isolate host X",
    "Block IP Y at firewall",
    "Hunt for technique Z across fleet"
  ],
  "iocs": {"ips": [], "domains": [], "hashes": [], "urls": []}
}"""

FEW_SHOT_EXAMPLES = [
    {
        "input": {"alert": "Wazuh alert 5715: PowerShell encoded command", "enrichment": {"ip": [{"data": {"abuse_confidence": 90}}]}, "entities": {"ip": ["192.168.1.50"]}},
        "output": {"summary": "Suspicious PowerShell encoded command executed on endpoint...", "mitre_mapping": [{"technique_id": "T1059.001", "tactic": "Execution", "confidence": 0.9, "evidence": "Base64-encoded PowerShell in command line"}]}
    }
]

class LLMAnalyzer:
    def __init__(self, model: str = "gpt-4o-mini", temperature: float = 0.1):
        self.model = model
        self.temperature = temperature
    
    def build_prompt(self, alert: "RawAlert", enrichment: Dict, mitre_mappings: List[Dict]) -> str:
        context = {
            "alert": alert.model_dump(),
            "enrichment_summary": self._summarize_enrichment(enrichment),
            "preliminary_mitre": mitre_mappings
        }
        return f"{SYSTEM_PROMPT}

Examples:
{FEW_SHOT_EXAMPLES}

Analyze:
{json.dumps(context, indent=2)}"
    
    async def analyze(self, alert, enrichment, mitre_mappings) -> Dict:
        # Use OpenAI, Anthropic, or local (Ollama/vLLM)
        pass