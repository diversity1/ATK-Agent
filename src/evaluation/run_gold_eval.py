"""
Gold-set and cross-library consistency evaluation.

Usage:
  python src/evaluation/run_gold_eval.py
  python src/evaluation/run_gold_eval.py --write-telemetry
  python src/evaluation/run_gold_eval.py --fixtures data/eval/gold_rules.jsonl --enable-llm
  python src/evaluation/run_gold_eval.py --disable-llm
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import config
from agents.langgraph_orchestrator import create_manager_agent
from core.registry import registry
from core.utils import ensure_dir
from dataio.load_attack import build_attack_index_from_raw, load_attack_index, attack_index_is_enriched
from dataio.save_results import (
    save_coverage_csv,
    save_rule_results_csv,
    save_rule_results_jsonl,
    save_run_report,
)
from evaluation.metrics_coverage import coverage_distortion_reduction
from llm.client import LLMClient
from tools.tag_validator_tool import check_parent_child_relation, is_valid_attack_tag, normalize_attack_tag


def load_fixtures(path: str) -> List[dict]:
    fixtures = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                fixtures.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_no}: {exc}") from exc
    return fixtures


def setup_runtime(enable_llm: Optional[bool] = None):
    if enable_llm is not None:
        config.ENABLE_LLM = enable_llm
    registry.clear()

    # The retriever is a module-level cache; reset it so evaluation always uses
    # the currently loaded ATT&CK index.
    try:
        import tools.attack_retriever_tool as retriever

        retriever._retriever_engine = None
    except Exception:
        pass

    if not os.path.exists(config.ATTACK_INDEX_PATH) and os.path.exists(config.RAW_ATTACK_PATH):
        attack_index = build_attack_index_from_raw(config.RAW_ATTACK_PATH, config.ATTACK_INDEX_PATH)
    else:
        attack_index = load_attack_index(config.ATTACK_INDEX_PATH)

    if not attack_index_is_enriched(attack_index) and os.path.exists(config.RAW_ATTACK_PATH):
        attack_index = build_attack_index_from_raw(config.RAW_ATTACK_PATH, config.ATTACK_INDEX_PATH)

    registry.register("attack_index", attack_index)
    llm_client = LLMClient()
    registry.register("llm_client", llm_client)
    return create_manager_agent()


def run_gold_eval(fixtures_path: str, enable_llm: Optional[bool] = None) -> dict:
    manager = setup_runtime(enable_llm)
    llm_client = registry.get("llm_client")
    fixtures = load_fixtures(fixtures_path)

    records = []
    rule_states = []
    for fixture in fixtures:
        state = manager.run_one_rule(
            fixture.get("raw_rule", {}),
            source_type=fixture.get("source_type", "sigma"),
            file_path=fixture.get("source_file", ""),
        )
        rule_states.append(state)
        record = manager._build_final_rule_record(state)
        record.update({
            "eval_id": fixture.get("eval_id", record.get("rule_id", "")),
            "equivalence_group": fixture.get("equivalence_group", ""),
            "gold_attack_tags": fixture.get("gold_attack_tags", []),
            "gold_action": fixture.get("gold_action", ""),
            "gold_rationale": fixture.get("gold_rationale", ""),
            "eval_errors": state.errors,
        })
        records.append(record)

    report = build_report(records)
    report["generated_at"] = datetime.now().isoformat(timespec="seconds")
    report["fixtures_path"] = fixtures_path
    report["enable_llm"] = bool(config.ENABLE_LLM)
    report["llm_available"] = bool(llm_client and llm_client.is_available())
    report["llm_provider"] = config.LLM_PROVIDER
    report["llm_model"] = config.LLM_MODEL
    return {"report": report, "records": records, "rule_states": rule_states, "manager": manager}


def build_report(records: List[dict]) -> dict:
    per_record = []
    top1_hits = 0
    top3_hits = 0
    compatible_top1_hits = 0
    compatible_top3_hits = 0
    action_hits = 0
    action_evaluated = 0
    precision_sum = 0.0
    recall_sum = 0.0
    f1_sum = 0.0
    rec_precision_sum = 0.0
    rec_recall_sum = 0.0
    rec_f1_sum = 0.0
    cdr_sum = 0.0
    recommended_cdr_sum = 0.0
    cdr_count = 0
    parent_child_corrections = 0
    parent_child_opportunities = 0

    for record in records:
        gold = _normalize_tags(record.get("gold_attack_tags", []))
        predicted_top1 = _normalize_tag(record.get("predicted_top1"))
        predicted_top3 = _normalize_tags(record.get("predicted_top3", []))
        final_tags = _normalize_tags(record.get("final_tags", []))
        suggested_tags = _normalize_tags(record.get("suggested_add_tags", []))
        recommended_tags = _dedupe_tags([*final_tags, *suggested_tags])
        existing = _normalize_tags(record.get("existing_attack_tags", []))

        top1_hit = bool(predicted_top1 and predicted_top1 in gold)
        top3_hit = bool(set(predicted_top3).intersection(gold))
        compatible_top1_hit = bool(predicted_top1 and any(_compatible(predicted_top1, tag) for tag in gold))
        compatible_top3_hit = bool(any(_compatible(pred, tag) for pred in predicted_top3 for tag in gold))

        precision, recall, f1 = _precision_recall_f1(set(final_tags), set(gold))
        rec_precision, rec_recall, rec_f1 = _precision_recall_f1(set(recommended_tags), set(gold))
        action_expected = record.get("gold_action", "")
        action_actual = record.get("action", "")
        action_evaluable = bool(action_expected)
        action_hit = bool(action_evaluable and action_actual == action_expected)

        cdr = coverage_distortion_reduction(set(existing), set(final_tags), set(gold)) if gold else 0.0
        recommended_cdr = coverage_distortion_reduction(set(existing), set(recommended_tags), set(gold)) if gold else 0.0
        if gold:
            cdr_sum += cdr
            recommended_cdr_sum += recommended_cdr
            cdr_count += 1

        if _has_parent_child_opportunity(existing, gold):
            parent_child_opportunities += 1
            if action_actual in {"REFINE_TO_SUBTECHNIQUE", "COARSEN_TO_PARENT"}:
                parent_child_corrections += 1

        top1_hits += int(top1_hit)
        top3_hits += int(top3_hit)
        compatible_top1_hits += int(compatible_top1_hit)
        compatible_top3_hits += int(compatible_top3_hit)
        action_hits += int(action_hit)
        action_evaluated += int(action_evaluable)
        precision_sum += precision
        recall_sum += recall
        f1_sum += f1
        rec_precision_sum += rec_precision
        rec_recall_sum += rec_recall
        rec_f1_sum += rec_f1

        per_record.append({
            "eval_id": record.get("eval_id", ""),
            "source_type": record.get("source_type", ""),
            "equivalence_group": record.get("equivalence_group", ""),
            "gold_attack_tags": gold,
            "predicted_top1": predicted_top1,
            "predicted_top3": predicted_top3,
            "final_tags": final_tags,
            "recommended_tags": recommended_tags,
            "action": action_actual,
            "gold_action": action_expected,
            "action_evaluable": action_evaluable,
            "top1_hit": top1_hit,
            "top3_hit": top3_hit,
            "compatible_top1_hit": compatible_top1_hit,
            "compatible_top3_hit": compatible_top3_hit,
            "action_hit": action_hit,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "recommendation_precision": rec_precision,
            "recommendation_recall": rec_recall,
            "recommendation_f1": rec_f1,
            "cdr": cdr,
            "recommended_cdr": recommended_cdr,
        })

    total = len(records)
    return {
        "overview": {
            "total_records": total,
            "sources": _count_by(records, "source_type"),
            "equivalence_groups": len({r.get("equivalence_group", "") for r in records if r.get("equivalence_group")}),
        },
        "gold_metrics": {
            "top1_accuracy": _ratio(top1_hits, total),
            "top3_accuracy": _ratio(top3_hits, total),
            "compatible_top1_accuracy": _ratio(compatible_top1_hits, total),
            "compatible_top3_accuracy": _ratio(compatible_top3_hits, total),
            "final_tag_precision": _ratio(precision_sum, total),
            "final_tag_recall": _ratio(recall_sum, total),
            "final_tag_f1": _ratio(f1_sum, total),
            "recommendation_precision": _ratio(rec_precision_sum, total),
            "recommendation_recall": _ratio(rec_recall_sum, total),
            "recommendation_f1": _ratio(rec_f1_sum, total),
            "action_accuracy": _ratio(action_hits, action_evaluated),
            "action_evaluated": action_evaluated,
            "mean_cdr": _ratio(cdr_sum, cdr_count),
            "recommended_mean_cdr": _ratio(recommended_cdr_sum, cdr_count),
            "parent_child_correction_rate": _ratio(parent_child_corrections, parent_child_opportunities),
        },
        "cross_library_consistency": compute_cross_library_consistency(records),
        "per_record": per_record,
    }


def compute_cross_library_consistency(records: List[dict]) -> dict:
    groups: Dict[str, List[dict]] = {}
    for record in records:
        group = record.get("equivalence_group", "")
        if group:
            groups.setdefault(group, []).append(record)

    evaluated = 0
    exact_top1_consistent = 0
    compatible_top1_consistent = 0
    details = []
    for group, items in groups.items():
        source_types = {item.get("source_type", "") for item in items}
        if len(items) < 2 or len(source_types) < 2:
            continue
        evaluated += 1
        top1s = [_normalize_tag(item.get("predicted_top1")) for item in items]
        top1s = [tag for tag in top1s if tag]
        exact = len(set(top1s)) == 1 if top1s else False
        compatible = bool(top1s) and all(_compatible(top1s[0], tag) for tag in top1s[1:])
        exact_top1_consistent += int(exact)
        compatible_top1_consistent += int(compatible)
        details.append({
            "equivalence_group": group,
            "size": len(items),
            "source_types": [item.get("source_type", "") for item in items],
            "top1s": top1s,
            "exact_top1_consistent": exact,
            "compatible_top1_consistent": compatible,
        })

    return {
        "evaluated_groups": evaluated,
        "exact_top1_consistency": _ratio(exact_top1_consistent, evaluated),
        "compatible_top1_consistency": _ratio(compatible_top1_consistent, evaluated),
        "details": details,
    }


def save_eval_outputs(result: dict, output_json: str, output_jsonl: str, output_csv: str, write_telemetry: bool):
    records = result["records"]
    report = result["report"]
    ensure_dir(os.path.dirname(output_json))

    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    save_rule_results_jsonl(records, output_jsonl)
    save_rule_results_csv(records, output_csv)

    if write_telemetry:
        manager = result["manager"]
        rule_states = result["rule_states"]
        ensure_dir(config.OUTPUTS_DIR)
        save_rule_results_jsonl(records, os.path.join(config.OUTPUTS_DIR, "rule_results.jsonl"))
        save_rule_results_csv(records, os.path.join(config.OUTPUTS_DIR, "rule_results.csv"))
        coverage_summary = manager._run_coverage(rule_states)
        save_coverage_csv(coverage_summary["technique_coverage"], os.path.join(config.OUTPUTS_DIR, "coverage_summary.csv"))
        save_coverage_csv(coverage_summary["tactic_coverage"], os.path.join(config.OUTPUTS_DIR, "coverage_by_tactic.csv"))
        save_run_report({
            "run_id": f"gold-eval-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "processed_rules": len(records),
            "source": "gold_eval",
        }, os.path.join(config.OUTPUTS_DIR, "run_report.json"))


def print_report(report: dict):
    overview = report["overview"]
    metrics = report["gold_metrics"]
    consistency = report["cross_library_consistency"]
    print("\nATK-Agent Gold Evaluation")
    print("=" * 60)
    print(f"Records             : {overview['total_records']}")
    print(f"Sources             : {overview['sources']}")
    print(f"Equivalence groups  : {overview['equivalence_groups']}")
    print("\nGold Metrics")
    print(f"Top-1 Accuracy      : {metrics['top1_accuracy']:.3f}")
    print(f"Top-3 Accuracy      : {metrics['top3_accuracy']:.3f}")
    print(f"Compatible Top-1    : {metrics['compatible_top1_accuracy']:.3f}")
    print(f"Compatible Top-3    : {metrics['compatible_top3_accuracy']:.3f}")
    print(f"Final Precision     : {metrics['final_tag_precision']:.3f}")
    print(f"Final Recall        : {metrics['final_tag_recall']:.3f}")
    print(f"Final F1            : {metrics['final_tag_f1']:.3f}")
    print(f"Recommend Precision : {metrics['recommendation_precision']:.3f}")
    print(f"Recommend Recall    : {metrics['recommendation_recall']:.3f}")
    print(f"Recommend F1        : {metrics['recommendation_f1']:.3f}")
    if metrics["action_evaluated"]:
        print(f"Action Accuracy     : {metrics['action_accuracy']:.3f} ({metrics['action_evaluated']} evaluated)")
    else:
        print("Action Accuracy     : n/a (0 evaluated)")
    print(f"Mean CDR            : {metrics['mean_cdr']:.3f}")
    print(f"Recommended Mean CDR: {metrics['recommended_mean_cdr']:.3f}")
    print(f"Parent-child Rate   : {metrics['parent_child_correction_rate']:.3f}")
    print("\nCross-library Consistency")
    print(f"Groups evaluated    : {consistency['evaluated_groups']}")
    print(f"Exact Top-1         : {consistency['exact_top1_consistency']:.3f}")
    print(f"Compatible Top-1    : {consistency['compatible_top1_consistency']:.3f}")
    print("=" * 60)


def _normalize_tag(tag) -> str:
    if tag is None:
        return ""
    text = str(tag).strip()
    if not text or not is_valid_attack_tag(text):
        return ""
    return normalize_attack_tag(text)


def _normalize_tags(tags) -> List[str]:
    if isinstance(tags, str):
        try:
            parsed = json.loads(tags)
            if isinstance(parsed, list):
                tags = parsed
        except Exception:
            tags = tags.strip("[]").replace("'", "").replace('"', "").split(",")
    if not isinstance(tags, list):
        tags = []
    normalized = []
    seen = set()
    for tag in tags:
        value = _normalize_tag(tag)
        if value and value not in seen:
            seen.add(value)
            normalized.append(value)
    return normalized


def _dedupe_tags(tags: List[str]) -> List[str]:
    seen = set()
    result = []
    for tag in tags:
        value = _normalize_tag(tag)
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _compatible(tag_a: str, tag_b: str) -> bool:
    if not tag_a or not tag_b:
        return False
    return tag_a == tag_b or check_parent_child_relation(tag_a, tag_b) or check_parent_child_relation(tag_b, tag_a)


def _precision_recall_f1(predicted: set, gold: set):
    if not gold and not predicted:
        return 1.0, 1.0, 1.0
    tp = len(predicted.intersection(gold))
    fp = len(predicted - gold)
    fn = len(gold - predicted)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1


def _has_parent_child_opportunity(existing: List[str], gold: List[str]) -> bool:
    return any(_compatible(old, new) and old != new for old in existing for new in gold)


def _count_by(records: List[dict], field: str) -> dict:
    counts = {}
    for record in records:
        value = record.get(field, "") or "unknown"
        counts[value] = counts.get(value, 0) + 1
    return counts


def _ratio(numerator: float, denominator: float) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run ATK-Agent gold-set evaluation.")
    parser.add_argument("--fixtures", default="data/eval/gold_rules.jsonl")
    parser.add_argument("--output-json", default="data/outputs/gold_eval_report.json")
    parser.add_argument("--output-jsonl", default="data/outputs/gold_eval_results.jsonl")
    parser.add_argument("--output-csv", default="data/outputs/gold_eval_results.csv")
    parser.add_argument("--write-telemetry", action="store_true",
                        help="Also write standard data/outputs/rule_results.* and coverage files for the Streamlit Enterprise Telemetry view.")
    llm_group = parser.add_mutually_exclusive_group()
    llm_group.add_argument("--enable-llm", dest="enable_llm", action="store_true",
                           help="Force LLM use if the configured provider is available.")
    llm_group.add_argument("--disable-llm", dest="enable_llm", action="store_false",
                           help="Force deterministic offline heuristic evaluation.")
    parser.set_defaults(enable_llm=None)
    args = parser.parse_args()

    result = run_gold_eval(args.fixtures, enable_llm=args.enable_llm)
    save_eval_outputs(result, args.output_json, args.output_jsonl, args.output_csv, args.write_telemetry)
    print_report(result["report"])
    print(f"Saved report: {args.output_json}")
    if args.write_telemetry:
        print("Enterprise Telemetry outputs written under data/outputs/.")
