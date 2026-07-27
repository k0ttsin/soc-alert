# enrichment/pipeline.py
import asyncio
from dataclasses import dataclass
from typing import Dict, Any
from abuseipdb_wrapper import AbuseIPDB
from OTXv2 import OTXv2, IndicatorTypes

@dataclass
class EnrichmentResult:
    indicator: str
    indicator_type: str
    source: str
    data: Dict[str, Any]
    confidence: float

class EnrichmentPipeline:
    def __init__(self, config: Dict):
        self.abuseipdb = AbuseIPDB(api_key=config.get("abuseipdb_key"), db_file="cache/abuseipdb.json")
        self.otx = OTXv2(config.get("otx_key")) if config.get("otx_key") else OTXv2("")
        
    async def enrich_ip(self, ip: str) -> List[EnrichmentResult]:
        results = []
        # AbuseIPDB (cached)
        abuse_data = self.abuseipdb.check_ip(ip)
        if abuse_data:
            results.append(EnrichmentResult(ip, "ip", "abuseipdb", abuse_data, 0.8))
        
        # OTX
        try:
            otx_data = self.otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)
            results.append(EnrichmentResult(ip, "ip", "otx", otx_data, 0.7))
        except: pass
        
        return results
    
    async def enrich_hash(self, file_hash: str) -> List[EnrichmentResult]:
        # OTX for file hashes
        try:
            otx_data = self.otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5, file_hash)
            return [EnrichmentResult(file_hash, "hash", "otx", otx_data, 0.7)]
        except: return []
    
    async def enrich_all(self, entities: Dict[str, List[str]]) -> Dict[str, List[EnrichmentResult]]:
        tasks = []
        for ip in entities.get("ip", []):
            tasks.append(self.enrich_ip(ip))
        for h in entities.get("hash", []):
            tasks.append(self.enrich_hash(h))
        # ... domain, url
        results = await asyncio.gather(*tasks)
        return dict(zip([f"{t[0]}_{t[1]}" for t in tasks], results))