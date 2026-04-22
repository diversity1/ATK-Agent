from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from .schemas import ParsedRule, AlignmentResult, RepairResult

class RuleProcessState(BaseModel):
    parsed_rule: Optional[ParsedRule] = None
    alignment_result: Optional[AlignmentResult] = None
    repair_result: Optional[RepairResult] = None
    errors: List[str] = []

    def add_error(self, error: str):
        self.errors.append(error)

class BatchProcessState(BaseModel):
    run_id: str
    rules: List[RuleProcessState] = []
    coverage_summary: Optional[Dict[str, Any]] = None
