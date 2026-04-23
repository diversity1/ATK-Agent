"""
run_eval.py
端到端的评测流水线 —— 直接读取 data/outputs/rule_results.csv 并输出评测报告

用法：
  cd atkagent
  python src/evaluation/run_eval.py
  python src/evaluation/run_eval.py --csv data/outputs/rule_results.csv --threshold 0.85
"""

import os
import sys
import csv
import json
import argparse
import ast
from datetime import datetime

# 确保 src 在 Python 路径中
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from evaluation.metrics_rule_level import (
    compute_macro_f1,
    compute_topk_accuracy,
    compute_repair_accuracy,
    compute_abstain_stats,
    compute_confidence_distribution,
    filter_silver_standard,
)
from evaluation.metrics_coverage import (
    gap_detection_stats,
    batch_cdr_stats,
)


# ------------------------------------------------------------------ #
# CSV 加载                                                             #
# ------------------------------------------------------------------ #

def load_csv_records(csv_path: str) -> list:
    records = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(dict(row))
    return records


# ------------------------------------------------------------------ #
# 报告打印                                                             #
# ------------------------------------------------------------------ #

def _bar(value: float, width: int = 30) -> str:
    filled = int(value * width)
    return "[" + "█" * filled + "·" * (width - filled) + f"] {value*100:.1f}%"


def print_report(report: dict):
    sep = "=" * 60

    print(f"\n{sep}")
    print(f"  ATK-Agent Evaluation Report")
    print(f"  Generated: {report['generated_at']}")
    print(sep)

    ov = report["overview"]
    print(f"\n[Overview]")
    print(f"  Total rules loaded : {ov['total_records']}")
    print(f"  Silver std (conf≥{ov['silver_threshold']:.0%}): {ov['silver_count']} rules")

    print(f"\n[Macro Metrics — on Silver Standard]")
    m = report["macro_metrics"]
    print(f"  Precision  : {_bar(m['precision'])}")
    print(f"  Recall     : {_bar(m['recall'])}")
    print(f"  F1-Score   : {_bar(m['f1'])}")
    print(f"  (evaluated {m['evaluated']} / {m['total']}, skipped {m['skipped']})")

    print(f"\n[Top-K Accuracy — on Silver Standard]")
    for k, acc in report["topk_accuracy"].items():
        print(f"  Top-{k[-1]} : {_bar(acc)}")

    print(f"\n[Coverage Analysis — on Silver Standard]")
    g = report["gap_stats"]
    if g:
        print(f"  Avg missing tags / rule  : {g['avg_missing_per_rule']:.2f}")
        print(f"  Avg extra tags / rule    : {g['avg_extra_per_rule']:.2f}")
        print(f"  Perfect coverage rate    : {_bar(g['perfect_coverage_rate'])}")

    print(f"\n[Coverage Distortion Reduction (CDR)]")
    cdr = report["cdr_stats"]
    if cdr:
        print(f"  Mean CDR   : {cdr['mean_cdr']:+.3f}  (>0 = repaired improved coverage)")
        print(f"  Improved   : {_bar(cdr['improved_ratio'])}")
        print(f"  Degraded   : {_bar(cdr['degraded_ratio'])}")

    print(f"\n[Repair Action Accuracy — on All Rules]")
    ra = report["repair_accuracy"]
    print(f"  Correct actions : {ra['correct']} / {ra['total']}")
    print(f"  Accuracy        : {_bar(ra['accuracy'])}")

    print(f"\n[Abstain Statistics]")
    ab = report["abstain_stats"]
    print(f"  Abstained : {ab['abstain_count']} / {ab['total']}  ({ab['ratio']*100:.1f}%)")

    print(f"\n[Confidence Distribution — All Rules]")
    for bucket, count in report["confidence_dist"].items():
        bar_len = min(count // 5, 40)
        print(f"  {bucket} : {'█' * bar_len} {count}")

    print(f"\n{sep}\n")


# ------------------------------------------------------------------ #
# 主函数                                                               #
# ------------------------------------------------------------------ #

def run(csv_path: str, threshold: float, output_json: str = None):
    if not os.path.exists(csv_path):
        print(f"[Error] CSV not found: {csv_path}")
        print("  Please run `python src/main.py` first to generate results.")
        sys.exit(1)

    print(f"Loading records from: {csv_path}")
    all_records = load_csv_records(csv_path)
    print(f"  Loaded {len(all_records)} rules.")

    silver = filter_silver_standard(all_records, threshold=threshold)
    print(f"  Silver standard (conf≥{threshold:.0%}): {len(silver)} rules.")

    report = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "overview": {
            "total_records":   len(all_records),
            "silver_count":    len(silver),
            "silver_threshold": threshold,
        },
        "macro_metrics":    compute_macro_f1(silver),
        "topk_accuracy": {
            "top1": compute_topk_accuracy(silver, k=1),
            "top3": compute_topk_accuracy(silver, k=3),
        },
        "gap_stats":        gap_detection_stats(silver),
        "cdr_stats":        batch_cdr_stats(silver),
        "repair_accuracy":  compute_repair_accuracy(all_records),
        "abstain_stats":    compute_abstain_stats(all_records),
        "confidence_dist":  compute_confidence_distribution(all_records),
    }

    print_report(report)

    if output_json:
        os.makedirs(os.path.dirname(output_json), exist_ok=True)
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"Full report saved → {output_json}")

    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ATK-Agent Evaluation Pipeline")
    parser.add_argument("--csv", default="data/outputs/rule_results.csv",
                        help="Path to rule_results.csv")
    parser.add_argument("--threshold", type=float, default=0.85,
                        help="Confidence threshold for Silver Standard (default: 0.85)")
    parser.add_argument("--output-json", default="data/outputs/eval_report.json",
                        help="Path to save full JSON report")
    args = parser.parse_args()

    run(csv_path=args.csv, threshold=args.threshold, output_json=args.output_json)
