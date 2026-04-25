def build_rerank_prompt(parsed_rule, candidates, semantic_profile=None, query_plan=None):
    cand_text = ""
    for idx, c in enumerate(candidates):
        tactic_str = ", ".join(c.tactics)
        logsource_score = c.why.get("logsource_score", 0)
        bm25_score = c.why.get("bm25_score", 0)
        breakdown = c.score_breakdown or c.why.get("score_breakdown", {})
        matched_sources = ", ".join(c.matched_data_sources or c.why.get("matched_data_sources", []))
        contradictions = "; ".join(c.contradictions or c.why.get("contradictions", []))
        cand_text += (
            f"{idx+1}. [{tactic_str}] {c.technique_id} - {c.technique_name} "
            f"(Retriever Score: {c.retrieval_score:.3f}, BM25: {bm25_score:.3f}, "
            f"LogSource Match: {logsource_score:.3f}, Evidence: {breakdown}, "
            f"Matched Data Sources: {matched_sources}, Contradictions: {contradictions})\n"
        )
        
    semantic_block = semantic_profile.model_dump() if semantic_profile else {}
    query_plan_block = query_plan.model_dump() if query_plan else {}

    return f"""You are an expert Security Operations Center (SOC) Analyst.
Your task is to accurately map a detection rule from any SIEM or detection-rule library to the MITRE ATT&CK framework.
Do NOT guess directly. You must follow a strict Chain of Thought (CoT) reasoning process.

Rule Source Type: {parsed_rule.source_type}
Rule Query Language: {parsed_rule.query_language}
Rule Title: {parsed_rule.title}
Rule Description: {parsed_rule.description}
Rule Log Source: product={parsed_rule.product}, category={parsed_rule.category}, service={parsed_rule.service}
Normalized Telemetry: {getattr(parsed_rule, "telemetry", [])}
Data Components: {getattr(parsed_rule, "data_components", [])}
Structured Observables: {getattr(parsed_rule, "observables", [])[:20]}
Rule Detection Logic: {parsed_rule.detection_text}
Original Tags: {parsed_rule.existing_attack_tags}
LLM Semantic Profile: {semantic_block}
Retrieval Query Plan: {query_plan_block}

Retrieved Candidates (Top matches from semantic search):
{cand_text}

Follow this 3-step reasoning process:
1. IOC Extraction: What specific tools, commands, APIs, or behaviors is this rule detecting?
2. Tactic Goal: Based on the behavior, what is the adversary's overarching goal (Tactic)?
3. Technique Selection: Look AT THE PROVIDED CANDIDATES ONLY. Which specific Technique or Sub-technique best describes the behavior under that Tactic?

Output strictly in the following JSON format:
{{
  "thought_process": {{
    "step1_extracted_behavior": "your analysis",
    "step2_tactic_goal": "your analysis",
    "step3_technique_matching": "your analysis"
  }},
  "top1": "TXXXX.XXX",
  "top3": ["TXXXX.XXX", ...],
  "confidence": 0.0 to 1.0 (float),
  "evidence_from_rule": ["short evidence from the rule"],
  "evidence_from_attack": ["short evidence from the chosen ATT&CK candidate"],
  "reason": "Summarize your thought process in 1 sentence.",
  "abstain": false
}}
"""
