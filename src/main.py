# main.py
import asyncio
from pathlib import Path
from models.alert import RawAlert
from enrichment.pipeline import EnrichmentPipeline
from mapping.mitre_mapper import MITREMapper
from analysis.llm_analyzer import LLMAnalyzer
from output.formatter import OutputFormatter

class SOCAssistant:
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)
        self.enrichment = EnrichmentPipeline(self.config["enrichment"])
        self.mitre = MITREMapper()
        self.llm = LLMAnalyzer(self.config["llm"]["model"])
        self.formatter = OutputFormatter()
    
    async def process_alert(self, raw_alert: Dict) -> Dict:
        # 1. Normalize
        alert = RawAlert(**raw_alert)
        
        # 2. Enrich (parallel)
        enrichment = await self.enrichment.enrich_all(alert.entities)
        
        # 3. MITRE Mapping
        mitre_mappings = self.mitre.map_alert_to_techniques(alert, enrichment)
        
        # 4. LLM Analysis
        llm_result = await self.llm.analyze(alert, enrichment, mitre_mappings)
        
        # 5. Generate Navigator Layer
        navigator_json = self.mitre.generate_navigator_layer(
            llm_result.get("mitre_mapping", [])
        )
        
        # 6. Format Output
        return self.formatter.format_final_output(
            alert=alert,
            enrichment=enrichment,
            mitre_mappings=mitre_mappings,
            llm_analysis=llm_result,
            navigator_layer=navigator_json
        )

# CLI Entry Point
async def main():
    assistant = SOCAssistant()
    
    # Example: Process from stdin (for SIEM webhook)
    import sys, json
    for line in sys.stdin:
        alert = json.loads(line)
        result = await assistant.process_alert(alert)
        print(json.dumps(result))

if __name__ == "__main__":
    asyncio.run(main())