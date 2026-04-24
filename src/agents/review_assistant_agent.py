from core.schemas import AlignmentResult, ParsedRule, RepairResult, ReviewBrief, SemanticProfile, VerificationResult
from llm.json_utils import parse_json_object


class ReviewAssistantAgent:
    def __init__(self, llm_client=None):
        self.llm_client = llm_client

    def process(
        self,
        parsed_rule: ParsedRule,
        semantic_profile: SemanticProfile,
        alignment_result: AlignmentResult,
        verification_result: VerificationResult,
        repair_result: RepairResult,
    ) -> ReviewBrief:
        if self.llm_client and self.llm_client.is_available():
            try:
                return self._build_with_llm(
                    parsed_rule,
                    semantic_profile,
                    alignment_result,
                    verification_result,
                    repair_result,
                )
            except Exception:
                return self._build_with_heuristic(
                    parsed_rule,
                    semantic_profile,
                    alignment_result,
                    verification_result,
                    repair_result,
                )
        return self._build_with_heuristic(
            parsed_rule,
            semantic_profile,
            alignment_result,
            verification_result,
            repair_result,
        )

    def _build_with_llm(
        self,
        parsed_rule: ParsedRule,
        semantic_profile: SemanticProfile,
        alignment_result: AlignmentResult,
        verification_result: VerificationResult,
        repair_result: RepairResult,
    ) -> ReviewBrief:
        prompt = f"""You are a SOC rule-governance review assistant.
Create a concise human review brief for an ATT&CK tag repair decision.

Rule title: {parsed_rule.title}
Existing tags: {parsed_rule.existing_attack_tags}
Semantic profile: {semantic_profile.model_dump()}
Alignment: {alignment_result.model_dump()}
Verification: {verification_result.model_dump()}
Repair decision: {repair_result.model_dump()}

Output strict JSON only:
{{
  "review_question": "question for the analyst",
  "analyst_summary": "short explanation",
  "evidence_table": [{{"source": "rule|attack|verification", "evidence": "..."}}],
  "recommended_final_tags": ["TXXXX"],
  "options": ["accept_suggestions", "keep_existing", "manual_edit"]
}}
"""
        raw = self.llm_client.chat([
            {"role": "system", "content": "Return ATT&CK review brief JSON only."},
            {"role": "user", "content": prompt},
        ])
        data = parse_json_object(raw)
        return ReviewBrief(
            review_question=str(data.get("review_question", "")),
            analyst_summary=str(data.get("analyst_summary", "")),
            evidence_table=[item for item in data.get("evidence_table", []) if isinstance(item, dict)],
            recommended_final_tags=self._list_of_strings(data.get("recommended_final_tags", [])),
            options=self._list_of_strings(data.get("options", [])) or self._default_options(),
            review_mode="llm",
        )

    def _build_with_heuristic(
        self,
        parsed_rule: ParsedRule,
        semantic_profile: SemanticProfile,
        alignment_result: AlignmentResult,
        verification_result: VerificationResult,
        repair_result: RepairResult,
    ) -> ReviewBrief:
        suggested = repair_result.suggested_add_tags
        suspect = repair_result.suspect_remove_tags
        question = "Review ATT&CK tag recommendations for this rule."
        if suggested or suspect:
            question = "Should the suggested ATT&CK tag changes be accepted?"

        evidence_table = [
            {"source": "rule", "evidence": semantic_profile.main_behavior or parsed_rule.title},
            {"source": "alignment", "evidence": f"top1={alignment_result.top1}, confidence={alignment_result.confidence:.2f}"},
            {"source": "verification", "evidence": verification_result.reason},
        ]
        if suggested:
            evidence_table.append({"source": "repair", "evidence": f"Suggested additions: {', '.join(suggested)}"})
        if suspect:
            evidence_table.append({"source": "repair", "evidence": f"Suspect removals: {', '.join(suspect)}"})

        recommended = repair_result.final_tags
        if repair_result.action == "POSSIBLE_MISMATCH" and suggested:
            recommended = suggested

        return ReviewBrief(
            review_question=question,
            analyst_summary=repair_result.repair_reason,
            evidence_table=evidence_table,
            recommended_final_tags=recommended,
            options=self._default_options(),
            review_mode="heuristic",
        )

    @staticmethod
    def _default_options():
        return ["accept_suggestions", "keep_existing", "manual_edit"]

    @staticmethod
    def _list_of_strings(value):
        if not isinstance(value, list):
            return []
        return [str(item).strip() for item in value if str(item).strip()]
