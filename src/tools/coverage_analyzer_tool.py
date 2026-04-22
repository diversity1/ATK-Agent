import csv
from typing import List
from core.state import RuleProcessState

def summarize_by_technique(rule_results: List[RuleProcessState], attack_index: dict) -> dict:
    tech_counts = {}
    for res in rule_results:
        if res.repair_result:
            for tag in res.repair_result.final_tags:
                tech_counts[tag] = tech_counts.get(tag, 0) + 1
    return tech_counts

def summarize_by_tactic(rule_results: List[RuleProcessState], attack_index: dict) -> dict:
    tactic_counts = {}
    for res in rule_results:
        if res.repair_result:
            for tag in res.repair_result.final_tags:
                doc = attack_index.get(tag, {})
                for tactic in doc.get("tactics", []):
                    tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
    return tactic_counts

def find_uncovered_techniques(rule_results: List[RuleProcessState], attack_index: dict) -> List[str]:
    covered = set()
    for res in rule_results:
        if res.repair_result:
            for tag in res.repair_result.final_tags:
                covered.add(tag)
                
    uncovered = []
    for tid in attack_index.keys():
        if tid not in covered:
            uncovered.append(tid)
    return uncovered

def compare_before_after(original_results: List[dict], repaired_results: List[RuleProcessState], attack_index: dict) -> dict:
    # Just a placeholder for the actual complex comparison logic
    return {"status": "comparison_done"}

def save_coverage_outputs(summary: dict, path: str):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Key", "Count"])
        for k, v in summary.items():
            writer.writerow([k, v])
