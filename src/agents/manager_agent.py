from typing import List, Dict, Any
from core.state import RuleProcessState, BatchProcessState
from core.registry import registry
from agents.parsing_agent import ParsingAgent
from agents.alignment_agent import AlignmentAgent
from agents.repair_agent import RepairAgent
from tools.coverage_analyzer_tool import summarize_by_technique, summarize_by_tactic
import uuid

class ManagerAgent:
    def __init__(self):
        self.parsing_agent = ParsingAgent()
        self.alignment_agent = AlignmentAgent(registry.get("attack_index"), registry.get("llm_client"))
        self.repair_agent = RepairAgent()

    def run_one_rule(self, raw_rule: dict, source_type: str = "sigma", file_path: str = "") -> RuleProcessState:
        state = RuleProcessState()
        try:
            parsed = self.parsing_agent.process(raw_rule, source_type, file_path)
            state.parsed_rule = parsed
            
            alignment = self.alignment_agent.process(parsed)
            state.alignment_result = alignment
            
            repair = self.repair_agent.process(parsed, alignment)
            state.repair_result = repair
            
        except Exception as e:
            state.add_error(str(e))
            
        return state

    def run_batch(self, raw_rules: List[dict], source_type: str = "sigma") -> BatchProcessState:
        batch_state = BatchProcessState(run_id=str(uuid.uuid4()))
        
        try:
            from tqdm import tqdm
            rule_iterator = tqdm(raw_rules, desc="Processing Rules", unit="rule")
        except ImportError:
            rule_iterator = raw_rules

        for rule in rule_iterator:
            state = self.run_one_rule(rule, source_type)
            batch_state.rules.append(state)
            
        batch_state.coverage_summary = self._run_coverage(batch_state.rules)
        return batch_state

    def _run_coverage(self, rule_states: List[RuleProcessState]) -> Dict[str, Any]:
        attack_index = registry.get("attack_index")
        return {
            "technique_coverage": summarize_by_technique(rule_states, attack_index),
            "tactic_coverage": summarize_by_tactic(rule_states, attack_index)
        }

    def _build_final_rule_record(self, rule_state: RuleProcessState) -> dict:
        record = {
            "rule_id": "unknown",
            "source_file": "",
            "title": "",
            "existing_attack_tags": [],
            "predicted_top1": None,
            "predicted_top3": [],
            "confidence": 0.0,
            "abstain": True,
            "action": "ERROR",
            "final_tags": [],
            "suggested_add_tags": [],
            "suspect_remove_tags": [],
            "needs_review": False,
            "mismatch_score": 0.0,
            "reason": "",
            "ranking_mode": "none"
        }
        
        if rule_state.parsed_rule:
            p = rule_state.parsed_rule
            record.update({
                "rule_id": p.rule_id,
                "source_file": p.source_file,
                "title": p.title,
                "existing_attack_tags": p.existing_attack_tags
            })
            
        if rule_state.alignment_result:
            a = rule_state.alignment_result
            record.update({
                "predicted_top1": a.top1,
                "predicted_top3": a.top3,
                "confidence": a.confidence,
                "abstain": a.abstain,
                "ranking_mode": a.ranking_mode
            })
            
        if rule_state.repair_result:
            r = rule_state.repair_result
            record.update({
                "action": r.action,
                "final_tags": r.final_tags,
                "suggested_add_tags": r.suggested_add_tags,
                "suspect_remove_tags": r.suspect_remove_tags,
                "needs_review": r.needs_review,
                "mismatch_score": r.mismatch_score,
                "reason": r.repair_reason
            })
            
        return record
