from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class DetectionRuleIR(BaseModel):
    rule_id: str
    source_type: str
    source_file: str = ""
    query_language: str = ""
    title: str = ""
    description: str = ""
    severity: str = ""
    status: str = ""
    product: str = ""
    category: str = ""
    service: str = ""
    platforms: List[str] = Field(default_factory=list)
    telemetry: List[str] = Field(default_factory=list)
    data_components: List[str] = Field(default_factory=list)
    observables: List[Dict[str, Any]] = Field(default_factory=list)
    entities: List[str] = Field(default_factory=list)
    detection_logic: Dict[str, Any] = Field(default_factory=dict)
    raw_tags: List[str] = Field(default_factory=list)
    existing_attack_tags: List[str] = Field(default_factory=list)
    behavior_summary: str = ""
    normalized_text: str = ""

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
    query_language: str = ""
    platforms: List[str] = Field(default_factory=list)
    telemetry: List[str] = Field(default_factory=list)
    data_components: List[str] = Field(default_factory=list)
    observables: List[Dict[str, Any]] = Field(default_factory=list)
    entities: List[str] = Field(default_factory=list)
    detection_logic: Dict[str, Any] = Field(default_factory=dict)
    behavior_summary: str = ""
    rule_ir: Optional[DetectionRuleIR] = None

class CandidateTechnique(BaseModel):
    technique_id: str
    technique_name: str
    retrieval_score: float
    tactics: List[str]
    platforms: List[str]
    why: Dict[str, Any]
    score_breakdown: Dict[str, float] = Field(default_factory=dict)
    matched_observables: List[Dict[str, Any]] = Field(default_factory=list)
    matched_data_sources: List[str] = Field(default_factory=list)
    contradictions: List[str] = Field(default_factory=list)

class SemanticProfile(BaseModel):
    main_behavior: str = ""
    observables: List[Dict[str, str]] = Field(default_factory=list)
    tools_or_binaries: List[str] = Field(default_factory=list)
    likely_tactics: List[str] = Field(default_factory=list)
    required_data_sources: List[str] = Field(default_factory=list)
    negative_constraints: List[str] = Field(default_factory=list)
    confidence: float = 0.0
    extraction_mode: str = "heuristic"

class QueryPlan(BaseModel):
    keyword_query: str = ""
    behavior_query: str = ""
    datasource_query: str = ""
    tactic_query: str = ""
    queries: List[str] = Field(default_factory=list)
    planning_mode: str = "heuristic"

class AlignmentResult(BaseModel):
    top1: Optional[str]
    top3: List[str]
    confidence: float
    reason: str
    thought_process: Optional[Dict[str, str]] = None
    evidence_from_rule: List[str] = Field(default_factory=list)
    evidence_from_attack: List[str] = Field(default_factory=list)
    score_breakdown: Dict[str, float] = Field(default_factory=dict)
    matched_observables: List[Dict[str, Any]] = Field(default_factory=list)
    matched_data_sources: List[str] = Field(default_factory=list)
    contradictions: List[str] = Field(default_factory=list)
    abstain: bool
    ranking_mode: str
    retrieved_candidates: List[CandidateTechnique]

class RepairResult(BaseModel):
    action: str  # KEEP, SUPPLEMENT, POSSIBLE_MISMATCH, ABSTAIN
    final_tags: List[str]
    suggested_add_tags: List[str] = Field(default_factory=list)
    suspect_remove_tags: List[str] = Field(default_factory=list)
    needs_review: bool = False
    mismatch_score: float
    repair_reason: str

class VerificationResult(BaseModel):
    verdict: str = "unknown"  # accept / revise / reject / unknown
    verified_top1: Optional[str] = None
    confidence_adjustment: float = 0.0
    contradictions: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    review_required: bool = False
    reason: str = ""
    verification_mode: str = "heuristic"

class ReviewBrief(BaseModel):
    review_question: str = ""
    analyst_summary: str = ""
    evidence_table: List[Dict[str, str]] = Field(default_factory=list)
    recommended_final_tags: List[str] = Field(default_factory=list)
    options: List[str] = Field(default_factory=list)
    review_mode: str = "heuristic"
