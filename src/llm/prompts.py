def build_rerank_prompt(parsed_rule, candidates):
    cand_text = ""
    for idx, c in enumerate(candidates):
        tactic_str = ", ".join(c.tactics)
        logsource_score = c.why.get("logsource_score", 0)
        bm25_score = c.why.get("bm25_score", 0)
        cand_text += (
            f"{idx+1}. [{tactic_str}] {c.technique_id} - {c.technique_name} "
            f"(Retriever Score: {c.retrieval_score:.3f}, BM25: {bm25_score:.3f}, "
            f"LogSource Match: {logsource_score:.3f})\n"
        )
        
    return f"""You are an expert Security Operations Center (SOC) Analyst.
Your task is to accurately map a Sigma detection rule to the MITRE ATT&CK framework.
Do NOT guess directly. You must follow a strict Chain of Thought (CoT) reasoning process.

Rule Title: {parsed_rule.title}
Rule Description: {parsed_rule.description}
Rule Log Source: product={parsed_rule.product}, category={parsed_rule.category}, service={parsed_rule.service}
Rule Detection Logic: {parsed_rule.detection_text}
Original Tags: {parsed_rule.existing_attack_tags}

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
  "reason": "Summarize your thought process in 1 sentence.",
  "abstain": false
}}
"""
