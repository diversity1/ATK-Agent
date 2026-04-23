from core.schemas import ParsedRule, AlignmentResult, RepairResult
from tools.tag_validator_tool import (
    check_parent_child_relation,
    compare_existing_and_predicted,
    compute_mismatch_score,
    is_valid_attack_tag,
    normalize_attack_tag,
)
import config


class RepairAgent:
    def process(self, parsed_rule: ParsedRule, alignment_result: AlignmentResult) -> RepairResult:
        comp, mismatch_score = self._validate_existing_tags(parsed_rule, alignment_result)
        action = self._decide_action(
            parsed_rule.existing_attack_tags,
            alignment_result.top3,
            alignment_result.confidence,
            mismatch_score,
        )
        decision = self._build_repair_decision(
            parsed_rule.existing_attack_tags,
            alignment_result.top3,
            alignment_result.confidence,
            action,
            comp,
        )

        return RepairResult(
            action=action,
            final_tags=decision["final_tags"],
            suggested_add_tags=decision["suggested_add_tags"],
            suspect_remove_tags=decision["suspect_remove_tags"],
            needs_review=decision["needs_review"],
            mismatch_score=mismatch_score,
            repair_reason=decision["reason"],
        )

    def _validate_existing_tags(self, parsed_rule: ParsedRule, alignment_result: AlignmentResult):
        comp = compare_existing_and_predicted(parsed_rule.existing_attack_tags, alignment_result.top3)
        mismatch_score = compute_mismatch_score(parsed_rule.existing_attack_tags, alignment_result.top3)
        return comp, mismatch_score

    def _decide_action(self, existing_tags: list, top_candidates: list, confidence: float, mismatch_score: float) -> str:
        if confidence < config.ABSTAIN_THRESHOLD:
            return "ABSTAIN"
        if not existing_tags:
            return "SUPPLEMENT"
        if mismatch_score > config.MISMATCH_THRESHOLD:
            return "POSSIBLE_MISMATCH"
        return "KEEP"

    def _build_repair_decision(self, existing_tags: list, top_candidates: list, confidence: float, action: str, comp: dict) -> dict:
        normalized_existing = self._normalize_tags(existing_tags)
        trusted_predictions = self._trusted_predictions(top_candidates, confidence)

        if action == "SUPPLEMENT":
            return {
                "final_tags": trusted_predictions,
                "suggested_add_tags": trusted_predictions,
                "suspect_remove_tags": [],
                "needs_review": False,
                "reason": f"No existing valid tags found. Auto-applied {len(trusted_predictions)} high-confidence prediction(s).",
            }

        if action == "KEEP":
            refinement_suggestions = []
            for pred in trusted_predictions:
                if pred in normalized_existing:
                    continue
                if any(check_parent_child_relation(ext, pred) for ext in normalized_existing):
                    refinement_suggestions.append(pred)

            refinement_suggestions = self._normalize_tags(refinement_suggestions)
            reason = "Existing tags remain the authoritative output."
            if refinement_suggestions:
                reason += " Added refinement suggestions where the model found a more specific sub-technique."

            return {
                "final_tags": normalized_existing,
                "suggested_add_tags": refinement_suggestions,
                "suspect_remove_tags": [],
                "needs_review": False,
                "reason": reason,
            }

        if action == "POSSIBLE_MISMATCH":
            suggested_add_tags = [
                tag for tag in trusted_predictions
                if not any(self._tags_compatible(tag, ext) for ext in normalized_existing)
            ]
            suspect_remove_tags = [
                tag for tag in normalized_existing
                if not any(self._tags_compatible(tag, pred) for pred in trusted_predictions)
            ]

            if not suggested_add_tags and not suspect_remove_tags:
                suggested_add_tags = trusted_predictions[:1]

            return {
                "final_tags": normalized_existing,
                "suggested_add_tags": self._normalize_tags(suggested_add_tags),
                "suspect_remove_tags": self._normalize_tags(suspect_remove_tags),
                "needs_review": True,
                "reason": (
                    "Detected a substantial mismatch between existing tags and predicted techniques. "
                    "Kept current tags unchanged and surfaced review recommendations."
                ),
            }

        return {
            "final_tags": normalized_existing,
            "suggested_add_tags": [],
            "suspect_remove_tags": [],
            "needs_review": False,
            "reason": "Low confidence alignment. Keeping original tags without automatic changes.",
        }

    def _trusted_predictions(self, top_candidates: list, confidence: float) -> list:
        normalized = self._normalize_tags(top_candidates)
        if not normalized:
            return []
        if confidence >= 0.93:
            return normalized[:3]
        if confidence >= config.CONFIDENCE_THRESHOLD:
            return normalized[:2]
        return normalized[:1]

    def _normalize_tags(self, tags: list) -> list:
        seen = set()
        ordered = []
        for tag in tags:
            if not is_valid_attack_tag(tag):
                continue
            normalized = normalize_attack_tag(tag)
            if normalized not in seen:
                seen.add(normalized)
                ordered.append(normalized)
        return ordered

    def _tags_compatible(self, tag_a: str, tag_b: str) -> bool:
        tag_a = normalize_attack_tag(tag_a)
        tag_b = normalize_attack_tag(tag_b)
        return (
            tag_a == tag_b
            or check_parent_child_relation(tag_a, tag_b)
            or check_parent_child_relation(tag_b, tag_a)
        )
