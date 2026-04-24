from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from .schemas import (
    AlignmentResult,
    ParsedRule,
    QueryPlan,
    RepairResult,
    ReviewBrief,
    SemanticProfile,
    VerificationResult,
)

class RuleProcessState(BaseModel):
    parsed_rule: Optional[ParsedRule] = None
    semantic_profile: Optional[SemanticProfile] = None
    query_plan: Optional[QueryPlan] = None
    alignment_result: Optional[AlignmentResult] = None
    verification_result: Optional[VerificationResult] = None
    repair_result: Optional[RepairResult] = None
    review_brief: Optional[ReviewBrief] = None
    errors: List[str] = Field(default_factory=list)
    graph_trace: List[str] = Field(default_factory=list)
    review_status: str = "not_required"
    orchestration_mode: str = "classic"

    def add_error(self, error: str):
        self.errors.append(error)

class BatchProcessState(BaseModel):
    run_id: str
    rules: List[RuleProcessState] = Field(default_factory=list)
    coverage_summary: Optional[Dict[str, Any]] = None
