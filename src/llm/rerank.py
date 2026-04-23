import json
from core.schemas import ParsedRule, AlignmentResult
from llm.prompts import build_rerank_prompt

def parse_llm_alignment_output(raw_text: str) -> dict:
    try:
        data = json.loads(raw_text)
        return data
    except Exception:
        # try to extract json from code block
        if "```json" in raw_text:
            block = raw_text.split("```json")[1].split("```")[0]
            return json.loads(block)
        return {}

def rerank_with_llm(parsed_rule: ParsedRule, candidates: list, llm_client) -> AlignmentResult:
    if not candidates:
        return fallback_to_heuristic(parsed_rule, candidates)
        
    prompt = build_rerank_prompt(parsed_rule, candidates)
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
        
    return AlignmentResult(
        top1=top1,
        top3=top3,
        confidence=data.get("confidence", 0.5),
        reason=data.get("reason", "LLM Reranked"),
        thought_process=data.get("thought_process", None),
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

    # Calibrate heuristic confidence for RRF-scale scores and logsource evidence.
    conf = 0.30
    conf += min(0.30, top_score * 3.0)
    conf += min(0.15, score_gap * 4.0)
    conf += min(0.15, logsource_score * 0.20)
    conf += 0.10 if hint_score > 0 else 0.0
    conf = min(0.95, conf)
    
    return AlignmentResult(
        top1=top1,
        top3=top3,
        confidence=conf,
        reason="Heuristic top-k",
        abstain=(conf < 0.3),
        ranking_mode="heuristic",
        retrieved_candidates=[c.model_dump() for c in candidates]
    )
