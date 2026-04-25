"""
Run rule-governance effect evaluation.

This implements experiment 4:
  - how many real rules need governance actions
  - how many tags are suggested for addition/removal
  - how large the analyst review queue is
  - how original/final/recommended ATT&CK coverage changes

Examples:
  python src/evaluation/run_governance_eval.py --fixtures data/eval/real_world_rules.jsonl --write-telemetry
  python src/evaluation/run_governance_eval.py --fixtures data/eval/real_world_rules.jsonl --disable-llm
"""

import argparse
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from evaluation.run_gold_eval import run_gold_eval, save_eval_outputs, print_report
from tools.governance_report_tool import (
    build_governance_summary,
    parse_list_cell,
    render_markdown_report,
    save_markdown_report,
)


def build_governance_effect(records: list) -> dict:
    original_counter = Counter()
    final_counter = Counter()
    recommended_counter = Counter()

    for record in records:
        existing = parse_list_cell(record.get("existing_attack_tags", []))
        final_tags = parse_list_cell(record.get("final_tags", []))
        suggested = parse_list_cell(record.get("suggested_add_tags", []))
        recommended = _dedupe([*final_tags, *suggested])

        original_counter.update(existing)
        final_counter.update(final_tags)
        recommended_counter.update(recommended)

    original_set = set(original_counter)
    final_set = set(final_counter)
    recommended_set = set(recommended_counter)

    return {
        "original_unique_techniques": len(original_set),
        "final_unique_techniques": len(final_set),
        "recommended_unique_techniques": len(recommended_set),
        "new_recommended_techniques": sorted(recommended_set - original_set),
        "removed_from_final_techniques": sorted(original_set - final_set),
        "top_original": original_counter.most_common(20),
        "top_final": final_counter.most_common(20),
        "top_recommended": recommended_counter.most_common(20),
    }


def _dedupe(values: list) -> list:
    seen = set()
    result = []
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def main():
    parser = argparse.ArgumentParser(description="Run governance-effect evaluation.")
    parser.add_argument("--fixtures", default="data/eval/real_world_rules.jsonl")
    parser.add_argument("--output-json", default="data/outputs/governance_eval_report.json")
    parser.add_argument("--output-jsonl", default="data/outputs/governance_eval_results.jsonl")
    parser.add_argument("--output-csv", default="data/outputs/governance_eval_results.csv")
    parser.add_argument("--markdown", default="data/outputs/governance_report.md")
    parser.add_argument("--write-telemetry", action="store_true")
    llm_group = parser.add_mutually_exclusive_group()
    llm_group.add_argument("--enable-llm", dest="enable_llm", action="store_true",
                           help="Force LLM use if the configured provider is available.")
    llm_group.add_argument("--disable-llm", dest="enable_llm", action="store_false",
                           help="Force deterministic offline heuristic evaluation.")
    parser.set_defaults(enable_llm=None)
    args = parser.parse_args()

    result = run_gold_eval(args.fixtures, enable_llm=args.enable_llm)
    records = result["records"]
    result["report"]["governance_summary"] = build_governance_summary(records)
    result["report"]["coverage_effect"] = build_governance_effect(records)

    save_eval_outputs(result, args.output_json, args.output_jsonl, args.output_csv, args.write_telemetry)

    markdown = render_markdown_report(records)
    save_markdown_report(markdown, args.markdown)

    print_report(result["report"])
    print("\nGovernance Summary")
    print(json.dumps(result["report"]["governance_summary"], indent=2, ensure_ascii=False))
    print("\nCoverage Effect")
    print(json.dumps(result["report"]["coverage_effect"], indent=2, ensure_ascii=False))
    print(f"\nSaved governance report: {args.output_json}")
    print(f"Saved markdown report: {args.markdown}")


if __name__ == "__main__":
    main()
