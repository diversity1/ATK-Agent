from core.schemas import ParsedRule, AlignmentResult, RepairResult
from tools.tag_validator_tool import compare_existing_and_predicted, compute_mismatch_score
import config

class RepairAgent:
    def process(self, parsed_rule: ParsedRule, alignment_result: AlignmentResult) -> RepairResult:
        comp, mismatch_score = self._validate_existing_tags(parsed_rule, alignment_result)
        
        action = self._decide_action(parsed_rule.existing_attack_tags, alignment_result.top3, alignment_result.confidence)
        final_tags, reason = self._build_final_tags(parsed_rule.existing_attack_tags, action, alignment_result.top3)
        
        return RepairResult(
            action=action,
            final_tags=final_tags,
            mismatch_score=mismatch_score,
            repair_reason=reason
        )

    def _validate_existing_tags(self, parsed_rule: ParsedRule, alignment_result: AlignmentResult):
        comp = compare_existing_and_predicted(parsed_rule.existing_attack_tags, alignment_result.top3)
        mismatch_score = compute_mismatch_score(parsed_rule.existing_attack_tags, alignment_result.top3)
        return comp, mismatch_score

    def _decide_action(self, existing_tags: list, top_candidates: list, confidence: float) -> str:
        if confidence < config.ABSTAIN_THRESHOLD:
            return "ABSTAIN"
        if not existing_tags:
            return "SUPPLEMENT"
        
        mismatch = compute_mismatch_score(existing_tags, top_candidates)
        if mismatch > config.MISMATCH_THRESHOLD:
            return "POSSIBLE_MISMATCH"
        
        return "KEEP"

    def _build_final_tags(self, existing_tags: list, action: str, top_candidates: list):
        if action == "KEEP":
            return list(set(existing_tags + top_candidates)), "Existing tags are consistent enough, supplemented with top candidates."
        elif action == "SUPPLEMENT":
            return top_candidates, "No existing valid tags found. Using top predicted candidates."
        elif action == "POSSIBLE_MISMATCH":
            # For now, keep existing but flag the mismatch
            return list(set(existing_tags + top_candidates)), "Significant mismatch detected between existing and predicted. Supplementing for coverage."
        else: # ABSTAIN
            return existing_tags, "Low confidence, keeping original tags."
