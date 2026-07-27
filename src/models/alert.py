# models/alert.py
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime
from enum import Enum

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class RawAlert(BaseModel):
    source: str                    # "wazuh", "elastic", "splunk"
    alert_id: str
    timestamp: datetime
    rule_id: str
    rule_description: str
    severity: Severity
    mitre_technique_ids: List[str] = []  # if already tagged
    entities: Dict[str, List[str]]       # {"ip": [...], "domain": [...], "hash": [...], "user": [...]}
    raw_log: str
    host: Optional[Dict] = None