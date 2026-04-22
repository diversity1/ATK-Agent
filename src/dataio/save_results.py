import json
import csv
from typing import List

def save_rule_results_jsonl(records: List[dict], path: str):
    with open(path, 'w', encoding='utf-8') as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")

def save_rule_results_csv(records: List[dict], path: str):
    if not records:
        return
    keys = records[0].keys()
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(records)

def save_run_report(report: dict, path: str):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

def save_coverage_csv(summary: dict, path: str):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Key", "Count"])
        for k, v in summary.items():
            writer.writerow([k, v])
