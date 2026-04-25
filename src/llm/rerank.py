import json
from core.schemas import ParsedRule, AlignmentResult
from llm.prompts import build_rerank_prompt
from llm.json_utils import parse_json_object

def parse_llm_alignment_output(raw_text: str) -> dict:
    return parse_json_object(raw_text)

def rerank_with_llm(parsed_rule: ParsedRule, candidates: list, llm_client, semantic_profile=None, query_plan=None) -> AlignmentResult:
    if not candidates:
        return fallback_to_heuristic(parsed_rule, candidates)
        
    prompt = build_rerank_prompt(parsed_rule, candidates, semantic_profile, query_plan)
    messages = [
        {"role": "system", "content": "You are a cybersecurity JSON API."},
        {"role": "user", "content": prompt}
    ]
    
    raw_response = llm_client.chat(messages)
    data = parse_llm_alignment_output(raw_response)
    
    top1 = data.get("top1")
    top3 = data.get("top3", [])
    if not top3 and top1:
        top3 = [top1]

    selected_candidate = _find_candidate(top1, candidates)
        
    return AlignmentResult(
        top1=top1,
        top3=top3,
        confidence=data.get("confidence", 0.5),
        reason=data.get("reason", "LLM Reranked"),
        thought_process=data.get("thought_process", None),
        evidence_from_rule=_list_of_strings(data.get("evidence_from_rule", [])),
        evidence_from_attack=_list_of_strings(data.get("evidence_from_attack", [])),
        score_breakdown=selected_candidate.score_breakdown if selected_candidate else {},
        matched_observables=selected_candidate.matched_observables if selected_candidate else [],
        matched_data_sources=selected_candidate.matched_data_sources if selected_candidate else [],
        contradictions=selected_candidate.contradictions if selected_candidate else [],
        abstain=data.get("abstain", False),
        ranking_mode="llm",
        retrieved_candidates=[c.model_dump() for c in candidates]
    )

def fallback_to_heuristic(parsed_rule: ParsedRule, candidates: list) -> AlignmentResult:
    if not candidates:
        return AlignmentResult(
            top1=None,
            top3=[],
            confidence=0.0,
            reason="No candidates retrieved",
            abstain=True,
            ranking_mode="heuristic",
            retrieved_candidates=[]
        )
        
    top1 = candidates[0].technique_id
    top3 = [c.technique_id for c in candidates[:3]]
    top_score = float(candidates[0].retrieval_score)
    second_score = float(candidates[1].retrieval_score) if len(candidates) > 1 else 0.0
    score_gap = max(0.0, top_score - second_score)
    logsource_score = float(candidates[0].why.get("logsource_score", 0.0))
    hint_score = float(candidates[0].why.get("hint_score", 0.0))
    contradiction_penalty = float(candidates[0].score_breakdown.get("contradiction_penalty", 0.0))

    # Calibrate heuristic confidence for RRF-scale scores and logsource evidence.
    conf = 0.30
    conf += min(0.30, top_score * 3.0)
    conf += min(0.15, score_gap * 4.0)
    conf += min(0.15, logsource_score * 0.20)
    conf += min(0.08, float(candidates[0].score_breakdown.get("entity_score", 0.0)) * 0.08)
    conf += min(0.08, float(candidates[0].score_breakdown.get("telemetry_score", 0.0)) * 0.08)
    conf += 0.10 if hint_score > 0 else 0.0
    conf -= min(0.15, contradiction_penalty * 0.10)
    conf = min(0.95, conf)
    
    return AlignmentResult(
        top1=top1,
        top3=top3,
        confidence=conf,
        reason="Heuristic top-k",
        evidence_from_rule=[],
        evidence_from_attack=[],
        score_breakdown=candidates[0].score_breakdown,
        matched_observables=candidates[0].matched_observables,
        matched_data_sources=candidates[0].matched_data_sources,
        contradictions=candidates[0].contradictions,
        abstain=(conf < 0.3),
        ranking_mode="heuristic",
        retrieved_candidates=[c.model_dump() for c in candidates]
    )

def _list_of_strings(value):
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _find_candidate(technique_id: str, candidates: list):
    if not technique_id:
        return candidates[0] if candidates else None
    for candidate in candidates:
        if candidate.technique_id == technique_id:
            return candidate
    return candidates[0] if candidates else None
