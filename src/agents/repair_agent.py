from core.schemas import ParsedRule, AlignmentResult, RepairResult
from tools.tag_validator_tool import (
    check_parent_child_relation,
    compare_existing_and_predicted,
    compute_mismatch_score,
    get_parent_technique,
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
            alignment_result,
        )
        decision = self._build_repair_decision(
            parsed_rule.existing_attack_tags,
            alignment_result.top3,
            alignment_result.confidence,
            action,
            comp,
            alignment_result,
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

    def _decide_action(
        self,
        existing_tags: list,
        top_candidates: list,
        confidence: float,
        mismatch_score: float,
        alignment_result: AlignmentResult,
    ) -> str:
        trusted_predictions = self._trusted_predictions(top_candidates, confidence)
        normalized_existing = self._normalize_tags(existing_tags)

        if confidence < config.ABSTAIN_THRESHOLD or not trusted_predictions:
            return "ABSTAIN"

        if not normalized_existing:
            return "ADD_CANDIDATE"

        if self._find_refinements(normalized_existing, trusted_predictions):
            return "REFINE_TO_SUBTECHNIQUE"

        if set(normalized_existing).intersection(set(trusted_predictions)):
            return "KEEP"

        if self._find_coarsening_targets(normalized_existing, trusted_predictions):
            return "COARSEN_TO_PARENT"

        if mismatch_score > config.MISMATCH_THRESHOLD:
            if any(not self._is_compatible_with_any(pred, normalized_existing) for pred in trusted_predictions):
                return "REPLACE_SUSPECT"
            return "REMOVE_SUSPECT"

        if getattr(alignment_result, "contradictions", None):
            return "REMOVE_SUSPECT"

        return "KEEP"

    def _build_repair_decision(
        self,
        existing_tags: list,
        top_candidates: list,
        confidence: float,
        action: str,
        comp: dict,
        alignment_result: AlignmentResult,
    ) -> dict:
        normalized_existing = self._normalize_tags(existing_tags)
        trusted_predictions = self._trusted_predictions(top_candidates, confidence)
        contradictions = getattr(alignment_result, "contradictions", []) or []
        contradiction_note = f" Candidate evidence has contradictions: {'; '.join(contradictions)}" if contradictions else ""

        if action == "ADD_CANDIDATE":
            needs_review = confidence < config.CONFIDENCE_THRESHOLD or bool(contradictions)
            return {
                "final_tags": trusted_predictions,
                "suggested_add_tags": trusted_predictions,
                "suspect_remove_tags": [],
                "needs_review": needs_review,
                "reason": (
                    f"No existing valid tags found. Proposed {len(trusted_predictions)} candidate tag(s)."
                    f"{contradiction_note}"
                ),
            }

        if action == "KEEP":
            return {
                "final_tags": normalized_existing,
                "suggested_add_tags": [],
                "suspect_remove_tags": [],
                "needs_review": bool(contradictions),
                "reason": f"Existing tags remain the authoritative output.{contradiction_note}",
            }

        if action == "REFINE_TO_SUBTECHNIQUE":
            refinement_suggestions = self._normalize_tags(
                self._find_refinements(normalized_existing, trusted_predictions)
            )
            return {
                "final_tags": normalized_existing,
                "suggested_add_tags": refinement_suggestions,
                "suspect_remove_tags": [],
                "needs_review": confidence < 0.90 or bool(contradictions),
                "reason": (
                    "Existing tag is a parent technique and the evidence supports a more specific sub-technique. "
                    "Kept the parent tag unchanged and surfaced the refinement as a suggestion."
                    f"{contradiction_note}"
                ),
            }

        if action == "COARSEN_TO_PARENT":
            parent_suggestions = self._normalize_tags(
                self._find_coarsening_targets(normalized_existing, trusted_predictions)
            )
            suspect_children = [
                tag for tag in normalized_existing
                if any(check_parent_child_relation(parent, tag) for parent in parent_suggestions)
            ]
            return {
                "final_tags": normalized_existing,
                "suggested_add_tags": parent_suggestions,
                "suspect_remove_tags": self._normalize_tags(suspect_children),
                "needs_review": True,
                "reason": (
                    "Existing tag is a sub-technique, but the evidence only supports the broader parent technique. "
                    "Kept current tags unchanged and requested analyst review."
                    f"{contradiction_note}"
                ),
            }

        if action == "REPLACE_SUSPECT":
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
                    f"{contradiction_note}"
                ),
            }

        if action == "REMOVE_SUSPECT":
            return {
                "final_tags": normalized_existing,
                "suggested_add_tags": [],
                "suspect_remove_tags": normalized_existing,
                "needs_review": True,
                "reason": (
                    "Existing tags are weakly supported or conflict with the candidate evidence. "
                    "Kept current tags unchanged and requested analyst review before removal."
                    f"{contradiction_note}"
                ),
            }

        return {
            "final_tags": normalized_existing,
            "suggested_add_tags": [],
            "suspect_remove_tags": [],
            "needs_review": bool(normalized_existing or trusted_predictions),
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

    def _find_refinements(self, existing_tags: list, predicted_tags: list) -> list:
        refinements = []
        for existing in existing_tags:
            for predicted in predicted_tags:
                if check_parent_child_relation(existing, predicted):
                    refinements.append(predicted)
        return self._normalize_tags(refinements)

    def _find_coarsening_targets(self, existing_tags: list, predicted_tags: list) -> list:
        parents = []
        for existing in existing_tags:
            for predicted in predicted_tags:
                if check_parent_child_relation(predicted, existing):
                    parents.append(predicted)
                else:
                    parent = get_parent_technique(existing)
                    if parent and parent == predicted and parent != existing:
                        parents.append(parent)
        return self._normalize_tags(parents)

    def _is_compatible_with_any(self, tag: str, candidates: list) -> bool:
        return any(self._tags_compatible(tag, candidate) for candidate in candidates)
