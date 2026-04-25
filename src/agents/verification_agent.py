from core.schemas import AlignmentResult, ParsedRule, SemanticProfile, VerificationResult
from llm.json_utils import parse_json_object


class VerificationAgent:
    def __init__(self, attack_index: dict, llm_client=None):
        self.attack_index = attack_index
        self.llm_client = llm_client

    def process(
        self,
        parsed_rule: ParsedRule,
        semantic_profile: SemanticProfile,
        alignment_result: AlignmentResult,
    ) -> VerificationResult:
        if self.llm_client and self.llm_client.is_available():
            try:
                return self._verify_with_llm(parsed_rule, semantic_profile, alignment_result)
            except Exception:
                return self._verify_with_heuristic(parsed_rule, semantic_profile, alignment_result)
        return self._verify_with_heuristic(parsed_rule, semantic_profile, alignment_result)

    def _verify_with_llm(
        self,
        parsed_rule: ParsedRule,
        semantic_profile: SemanticProfile,
        alignment_result: AlignmentResult,
    ) -> VerificationResult:
        candidate_context = []
        for candidate in alignment_result.retrieved_candidates[:5]:
            doc = self.attack_index.get(candidate.technique_id, {})
            candidate_context.append({
                "technique_id": candidate.technique_id,
                "name": candidate.technique_name,
                "tactics": candidate.tactics,
                "data_sources": doc.get("data_sources", []),
                "detection": (doc.get("detection", "") or "")[:500],
            })

        prompt = f"""You are an ATT&CK alignment verification API.
Critically verify whether the selected ATT&CK technique is supported by the rule evidence.

Rule:
source_type={parsed_rule.source_type}
query_language={parsed_rule.query_language}
title={parsed_rule.title}
description={parsed_rule.description}
logsource=product:{parsed_rule.product}, category:{parsed_rule.category}, service:{parsed_rule.service}
telemetry={parsed_rule.telemetry}
data_components={parsed_rule.data_components}
observables={parsed_rule.observables[:20]}
detection={parsed_rule.detection_text}

Semantic profile:
{semantic_profile.model_dump()}

Alignment result:
top1={alignment_result.top1}
top3={alignment_result.top3}
confidence={alignment_result.confidence}
reason={alignment_result.reason}

Candidate context:
{candidate_context}

Output strict JSON only:
{{
  "verdict": "accept|revise|reject",
  "verified_top1": "TXXXX or TXXXX.XXX",
  "confidence_adjustment": -0.2 to 0.2,
  "contradictions": ["..."],
  "missing_evidence": ["..."],
  "review_required": true,
  "reason": "one concise sentence"
}}
"""
        raw = self.llm_client.chat([
            {"role": "system", "content": "Return ATT&CK verification JSON only."},
            {"role": "user", "content": prompt},
        ])
        data = parse_json_object(raw)
        return VerificationResult(
            verdict=str(data.get("verdict", "unknown")),
            verified_top1=data.get("verified_top1") or alignment_result.top1,
            confidence_adjustment=self._clamp_adjustment(data.get("confidence_adjustment", 0.0)),
            contradictions=self._list_of_strings(data.get("contradictions", [])),
            missing_evidence=self._list_of_strings(data.get("missing_evidence", [])),
            review_required=bool(data.get("review_required", False)),
            reason=str(data.get("reason", "LLM verification completed.")),
            verification_mode="llm",
        )

    def _verify_with_heuristic(
        self,
        parsed_rule: ParsedRule,
        semantic_profile: SemanticProfile,
        alignment_result: AlignmentResult,
    ) -> VerificationResult:
        if not alignment_result.top1:
            return VerificationResult(
                verdict="reject",
                verified_top1=None,
                confidence_adjustment=-0.2,
                missing_evidence=["No ATT&CK top1 candidate was produced."],
                review_required=True,
                reason="No top candidate is available for verification.",
            )

        top_doc = self.attack_index.get(alignment_result.top1, {})
        rule_text = " ".join([
            parsed_rule.normalized_rule_text,
            semantic_profile.main_behavior,
            " ".join(semantic_profile.tools_or_binaries),
            " ".join(semantic_profile.required_data_sources),
            " ".join(getattr(parsed_rule, "telemetry", []) or []),
            " ".join(getattr(parsed_rule, "data_components", []) or []),
        ]).lower()
        doc_text = " ".join([
            top_doc.get("name", ""),
            top_doc.get("description", ""),
            top_doc.get("detection", ""),
            " ".join(top_doc.get("data_sources", []) or []),
        ]).lower()

        evidence_hits = 0
        for token in semantic_profile.tools_or_binaries:
            if token.lower() in doc_text:
                evidence_hits += 1
        for observable in semantic_profile.observables:
            value = str(observable.get("value", "")).lower()
            if value and value in doc_text:
                evidence_hits += 1

        top_candidate = alignment_result.retrieved_candidates[0] if alignment_result.retrieved_candidates else None
        logsource_score = float(top_candidate.why.get("logsource_score", 0.0)) if top_candidate else 0.0
        tactic_overlap = bool(set(semantic_profile.likely_tactics) & set(top_doc.get("tactics", []) or []))

        adjustment = 0.0
        missing_evidence = []
        if evidence_hits > 0:
            adjustment += 0.03
        if logsource_score >= 0.5:
            adjustment += 0.03
        if tactic_overlap:
            adjustment += 0.02
        if alignment_result.confidence < 0.45:
            adjustment -= 0.12
            missing_evidence.append("Alignment confidence is low.")
        if not evidence_hits and not logsource_score:
            adjustment -= 0.08
            missing_evidence.append("No direct tool, observable, or log-source evidence matched the top candidate.")

        verdict = "accept" if alignment_result.confidence + adjustment >= 0.5 else "revise"
        review_required = verdict != "accept" or bool(missing_evidence)
        if alignment_result.abstain:
            review_required = True

        return VerificationResult(
            verdict=verdict,
            verified_top1=alignment_result.top1,
            confidence_adjustment=self._clamp_adjustment(adjustment),
            contradictions=[],
            missing_evidence=missing_evidence,
            review_required=review_required,
            reason="Heuristic verification compared rule evidence with the top ATT&CK candidate.",
            verification_mode="heuristic",
        )

    @staticmethod
    def _clamp_adjustment(value) -> float:
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            numeric = 0.0
        return max(-0.2, min(0.2, numeric))

    @staticmethod
    def _list_of_strings(value):
        if not isinstance(value, list):
            return []
        return [str(item).strip() for item in value if str(item).strip()]
