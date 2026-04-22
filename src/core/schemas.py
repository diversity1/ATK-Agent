from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class ParsedRule(BaseModel):
    rule_id: str
    source_type: str  # sigma / splunk
    source_file: str
    title: str
    description: str
    product: str
    category: str
    service: str
    detection_text: str
    raw_tags: List[str]
    existing_attack_tags: List[str]
    normalized_rule_text: str

class CandidateTechnique(BaseModel):
    technique_id: str
    technique_name: str
    retrieval_score: float
    tactics: List[str]
    platforms: List[str]
    why: Dict[str, Any]

class AlignmentResult(BaseModel):
    top1: Optional[str]
    top3: List[str]
    confidence: float
    reason: str
    thought_process: Optional[Dict[str, str]] = None
    abstain: bool
    ranking_mode: str
    retrieved_candidates: List[CandidateTechnique]

class RepairResult(BaseModel):
    action: str  # KEEP, SUPPLEMENT, POSSIBLE_MISMATCH, ABSTAIN
    final_tags: List[str]
    mismatch_score: float
    repair_reason: str
