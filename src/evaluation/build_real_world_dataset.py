"""
Build real-world evaluation fixtures from open detection-rule repositories.

Supported sources:
  - SigmaHQ-style Sigma YAML rules
  - Splunk Security Content YAML/JSON/SPL rules

Examples:
  python src/evaluation/build_real_world_dataset.py --sigma-root data/sigma_rules --max-sigma 200
  python src/evaluation/build_real_world_dataset.py --sigma-root data/sigma_rules --splunk-root data/external/security_content --max-sigma 200 --max-splunk 200
"""

import argparse
import json
import os
import random
import sys
from typing import Any, Dict, Iterable, List

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parsers.registry import get_rule_adapter


def load_rule_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        if path.endswith((".yml", ".yaml")):
            return yaml.safe_load(f)
        if path.endswith(".json"):
            return json.load(f)
        if path.endswith((".spl", ".txt")):
            return {"name": os.path.basename(path), "search": f.read()}
    return None


def iter_rule_paths(root: str, exts: Iterable[str]) -> Iterable[str]:
    if not root or not os.path.exists(root):
        return []
    paths = []
    for current_root, _, files in os.walk(root):
        for name in files:
            if name.lower().endswith(tuple(exts)):
                paths.append(os.path.join(current_root, name))
    return paths


def build_fixtures_from_source(source_type: str, root: str, max_records: int, seed: int) -> List[dict]:
    if not root or not os.path.exists(root):
        return []

    adapter = get_rule_adapter(source_type)
    exts = [".yml", ".yaml"] if source_type == "sigma" else [".yml", ".yaml", ".json", ".spl", ".txt"]
    paths = list(iter_rule_paths(root, exts))
    random.Random(seed).shuffle(paths)

    fixtures = []
    seen_ids = set()
    for path in paths:
        try:
            raw_rule = load_rule_file(path)
            if not isinstance(raw_rule, dict):
                continue
            raw_rule["_source_file"] = path
            rule_ir = adapter.parse(raw_rule, path)
        except Exception:
            continue

        gold_tags = rule_ir.existing_attack_tags
        if not gold_tags:
            continue

        eval_id = f"{source_type}:{rule_ir.rule_id}"
        if eval_id in seen_ids:
            eval_id = f"{eval_id}:{len(fixtures)}"
        seen_ids.add(eval_id)

        fixtures.append({
            "eval_id": eval_id,
            "equivalence_group": _equivalence_group(gold_tags),
            "source_type": source_type,
            "source_file": path,
            "gold_attack_tags": gold_tags,
            "gold_action": "",
            "gold_rationale": (
                "Silver label from the original open-source detection rule. "
                "Use as a real-world evaluation reference, not as a manually adjudicated gold label."
            ),
            "raw_rule": _strip_internal_fields(raw_rule),
        })
        if max_records and len(fixtures) >= max_records:
            break
    return fixtures


def write_jsonl(records: List[dict], path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")


def _equivalence_group(tags: List[str]) -> str:
    if not tags:
        return ""
    return "attack:" + tags[0]


def _strip_internal_fields(rule: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in rule.items() if not str(key).startswith("_")}


def main():
    parser = argparse.ArgumentParser(description="Build real-world ATK-Agent evaluation fixtures.")
    parser.add_argument("--sigma-root", default="data/sigma_rules")
    parser.add_argument("--splunk-root", default="data/external/security_content")
    parser.add_argument("--output", default="data/eval/real_world_rules.jsonl")
    parser.add_argument("--max-sigma", type=int, default=200)
    parser.add_argument("--max-splunk", type=int, default=200)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    sigma_fixtures = build_fixtures_from_source("sigma", args.sigma_root, args.max_sigma, args.seed)
    splunk_fixtures = build_fixtures_from_source("splunk", args.splunk_root, args.max_splunk, args.seed + 1)
    fixtures = [*sigma_fixtures, *splunk_fixtures]

    write_jsonl(fixtures, args.output)
    print(f"Saved {len(fixtures)} real-world fixtures -> {args.output}")
    print(f"  sigma : {len(sigma_fixtures)}")
    print(f"  splunk: {len(splunk_fixtures)}")
    if not splunk_fixtures:
        print("  note  : no Splunk fixtures found. Provide --splunk-root pointing to a local Splunk Security Content checkout.")


if __name__ == "__main__":
    main()
