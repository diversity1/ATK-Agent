"""
Run label-repair experiments by injecting controlled ATT&CK tag noise.

This implements experiment 3:
  - missing-tag recovery
  - wrong-tag detection
  - parent/child technique correction

Examples:
  python src/evaluation/run_noise_repair_eval.py --fixtures data/eval/real_world_rules.jsonl --noise mixed --ratio 0.5
  python src/evaluation/run_noise_repair_eval.py --fixtures data/eval/gold_rules.jsonl --noise parent_child --ratio 1.0 --write-telemetry
  python src/evaluation/run_noise_repair_eval.py --fixtures data/eval/real_world_rules.jsonl --disable-llm
"""

import argparse
import copy
import json
import os
import random
import sys
from typing import List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dataio.load_attack import load_attack_index
import config
from evaluation.run_gold_eval import run_gold_eval, save_eval_outputs, print_report
from tools.tag_validator_tool import get_parent_technique, is_valid_attack_tag, normalize_attack_tag


COMMON_WRONG_TAGS = [
    "T1059",
    "T1027",
    "T1003",
    "T1053",
    "T1547.001",
    "T1110",
    "T1105",
    "T1047",
    "T1562.001",
]


def load_fixtures(path: str) -> List[dict]:
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def build_noisy_fixtures(fixtures: List[dict], noise: str, ratio: float, seed: int, wrong_pool: List[str]) -> List[dict]:
    rng = random.Random(seed)
    noisy = []
    for fixture in fixtures:
        item = copy.deepcopy(fixture)
        gold_tags = _normalize_tags(item.get("gold_attack_tags", []))
        if not gold_tags or rng.random() > ratio:
            noisy.append(item)
            continue

        selected_noise = noise
        if noise == "mixed":
            selected_noise = rng.choice(["missing_tag", "wrong_technique", "parent_child"])

        noisy_tags = list(gold_tags)
        if selected_noise == "missing_tag":
            noisy_tags = []
            item["gold_action"] = "ADD_CANDIDATE"
            item["noise_type"] = "missing_tag"
        elif selected_noise == "wrong_technique":
            wrong = _pick_wrong_tag(gold_tags, wrong_pool, rng)
            noisy_tags = [wrong]
            item["gold_action"] = "REPLACE_SUSPECT"
            item["noise_type"] = "wrong_technique"
        elif selected_noise == "parent_child":
            parent_tags = [get_parent_technique(tag) for tag in gold_tags if "." in tag]
            parent_tags = [tag for tag in parent_tags if tag]
            if parent_tags:
                noisy_tags = parent_tags
                item["gold_action"] = "REFINE_TO_SUBTECHNIQUE"
                item["noise_type"] = "parent_child"
            else:
                wrong = _pick_wrong_tag(gold_tags, wrong_pool, rng)
                noisy_tags = [wrong]
                item["gold_action"] = "REPLACE_SUSPECT"
                item["noise_type"] = "wrong_technique"
        else:
            raise ValueError(f"Unsupported noise type: {noise}")

        item["original_attack_tags"] = gold_tags
        item["noisy_attack_tags"] = noisy_tags
        item["raw_rule"] = _set_rule_attack_tags(item.get("raw_rule", {}), item.get("source_type", "sigma"), noisy_tags)
        noisy.append(item)
    return noisy


def save_jsonl(records: List[dict], path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _set_rule_attack_tags(raw_rule: dict, source_type: str, tags: List[str]) -> dict:
    raw_rule = copy.deepcopy(raw_rule or {})
    if source_type == "sigma":
        raw_rule["tags"] = [f"attack.{tag.lower()}" for tag in tags]
    elif source_type == "splunk":
        raw_tags = raw_rule.get("tags", {})
        if not isinstance(raw_tags, dict):
            raw_tags = {}
        raw_tags["mitre_attack_id"] = tags
        raw_rule["tags"] = raw_tags
    else:
        raw_rule["tags"] = tags
    return raw_rule


def _normalize_tags(tags) -> List[str]:
    result = []
    for tag in tags or []:
        text = str(tag).strip()
        if is_valid_attack_tag(text):
            result.append(normalize_attack_tag(text))
    return result


def _pick_wrong_tag(gold_tags: List[str], wrong_pool: List[str], rng: random.Random) -> str:
    choices = [tag for tag in wrong_pool if tag not in gold_tags]
    return rng.choice(choices or COMMON_WRONG_TAGS)


def _load_wrong_pool() -> List[str]:
    try:
        attack_index = load_attack_index(config.ATTACK_INDEX_PATH)
        keys = [key for key in attack_index.keys() if is_valid_attack_tag(key)]
        return keys or COMMON_WRONG_TAGS
    except Exception:
        return COMMON_WRONG_TAGS


def main():
    parser = argparse.ArgumentParser(description="Run noisy label-repair evaluation.")
    parser.add_argument("--fixtures", default="data/eval/real_world_rules.jsonl")
    parser.add_argument("--noise", choices=["missing_tag", "wrong_technique", "parent_child", "mixed"], default="mixed")
    parser.add_argument("--ratio", type=float, default=0.5)
    parser.add_argument("--seed", type=int, default=11)
    parser.add_argument("--output-fixtures", default="data/eval/noisy_rules.jsonl")
    parser.add_argument("--output-json", default="data/outputs/noise_repair_report.json")
    parser.add_argument("--output-jsonl", default="data/outputs/noise_repair_results.jsonl")
    parser.add_argument("--output-csv", default="data/outputs/noise_repair_results.csv")
    parser.add_argument("--write-telemetry", action="store_true")
    llm_group = parser.add_mutually_exclusive_group()
    llm_group.add_argument("--enable-llm", dest="enable_llm", action="store_true",
                           help="Force LLM use if the configured provider is available.")
    llm_group.add_argument("--disable-llm", dest="enable_llm", action="store_false",
                           help="Force deterministic offline heuristic evaluation.")
    parser.set_defaults(enable_llm=None)
    args = parser.parse_args()

    fixtures = load_fixtures(args.fixtures)
    noisy = build_noisy_fixtures(fixtures, args.noise, args.ratio, args.seed, _load_wrong_pool())
    save_jsonl(noisy, args.output_fixtures)
    print(f"Saved noisy fixtures -> {args.output_fixtures}")

    result = run_gold_eval(args.output_fixtures, enable_llm=args.enable_llm)
    result["report"]["noise_config"] = {
        "source_fixtures": args.fixtures,
        "noise": args.noise,
        "ratio": args.ratio,
        "seed": args.seed,
    }
    save_eval_outputs(result, args.output_json, args.output_jsonl, args.output_csv, args.write_telemetry)
    print_report(result["report"])
    print(f"Saved noise repair report: {args.output_json}")


if __name__ == "__main__":
    main()
