# mapping/mitre_mapper.py
from attackcti import attack_client
from mitreattack.navlayers import Layer, Gradient
from typing import List, Dict

class MITREMapper:
    def __init__(self):
        self.client = attack_client()
        self.technique_cache = {}
        self._build_cache()
    
    def _build_cache(self):
        """Pre-load all techniques for fast lookup"""
        enterprises = self.client.get_enterprise_techniques()
        for tech in enterprises:
            tid = tech.get("external_references", [{}])[0].get("external_id", "")
            if tid.startswith("T"):
                self.technique_cache[tid] = tech
    
    def map_alert_to_techniques(self, alert: "RawAlert", enrichment: Dict) -> List[Dict]:
        """Map alert + enrichment to MITRE techniques with confidence scores"""
        techniques = []
        
        # 1. Explicit tags from SIEM rule
        for tid in alert.mitre_technique_ids:
            techniques.append({"technique_id": tid, "source": "siem_rule", "confidence": 0.9})
        
        # 2. Behavior-based inference from enrichment
        for result in enrichment.get("ip", []):
            if result.data.get("malicious_activity"):
                # Map known malicious IP behaviors
                techniques.extend(self._infer_from_ip_behavior(result.data))
        
        for result in enrichment.get("hash", []):
            # Map malware family to techniques
            malware_families = result.data.get("malware_families", [])
            for fam in malware_families:
                techniques.extend(self._get_techniques_for_malware(fam))
        
        # Deduplicate & score
        return self._deduplicate_and_score(techniques)
    
    def get_technique_details(self, technique_id: str) -> Dict:
        return self.technique_cache.get(technique_id, {})
    
    def generate_navigator_layer(self, techniques: List[Dict]) -> Dict:
        """Generate ATT&CK Navigator JSON for visualization"""
        layer = Layer(name="SOC Alert Analysis", domain="enterprise-attack")
        gradient = Gradient(colors=["#ffffff", "#ff6600"], min_value=0, max_value=100)
        for t in techniques:
            layer.add_technique(
                technique_id=t["technique_id"],
                score=t.get("confidence", 0) * 100,
                comment=t.get("reasoning", ""),
                gradient=gradient
            )
        return layer.to_dict()