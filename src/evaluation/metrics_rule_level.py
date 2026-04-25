"""
metrics_rule_level.py
规则级别的定量评测指标（全部真实实现，不再是 mock）

核心思路：
  - 以 predicted_top3 作为系统给出的预测集合
  - 以 existing_attack_tags 作为参考标签（Gold/Silver Standard）
  - 在 "Silver Eval" 模式下只评测 confidence >= threshold 的样本
"""

from typing import List, Dict, Any


# --------------------------------------------------------------------------- #
# 基础指标计算                                                                 #
# --------------------------------------------------------------------------- #

def _parse_tag_list(raw) -> set:
    """将 CSV 中可能是字符串表示的列表解析为 set，如 "['T1059', 'T1027']" """
    if isinstance(raw, list):
        return set(raw)
    if isinstance(raw, str):
        import ast
        try:
            lst = ast.literal_eval(raw)
            if isinstance(lst, list):
                return set(str(t).strip() for t in lst)
        except Exception:
            pass
        # 降级：直接 split
        raw = raw.strip("[]").replace("'", "").replace('"', "")
        return set(t.strip() for t in raw.split(",") if t.strip())
    return set()


def _parse_tag_sequence(raw) -> list:
    if isinstance(raw, list):
        return [str(t).strip() for t in raw if str(t).strip()]
    if isinstance(raw, str):
        import ast
        try:
            lst = ast.literal_eval(raw)
            if isinstance(lst, list):
                return [str(t).strip() for t in lst if str(t).strip()]
        except Exception:
            pass
        raw = raw.strip("[]").replace("'", "").replace('"', "")
        return [t.strip() for t in raw.split(",") if t.strip()]
    return []


def precision_recall_f1_per_record(record: dict,
                                   pred_field: str = "predicted_top3",
                                   gold_field: str = "existing_attack_tags"
                                   ) -> dict:
    """计算单条规则的 Precision / Recall / F1（集合匹配）"""
    gold = _parse_tag_list(record.get(gold_field, []))
    pred = _parse_tag_list(record.get(pred_field, []))

    tp = len(gold & pred)
    fp = len(pred - gold)
    fn = len(gold - pred)

    precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if not pred else 0.0)
    recall    = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if not gold else 0.0)
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)

    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1}


# --------------------------------------------------------------------------- #
# 宏平均指标                                                                   #
# --------------------------------------------------------------------------- #

def compute_macro_f1(records: list,
                     pred_field: str = "predicted_top3",
                     gold_field: str = "existing_attack_tags") -> dict:
    """计算宏平均 Precision / Recall / F1"""
    if not records:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0,
                "total": 0, "skipped": 0}

    precisions, recalls, f1s = [], [], []
    skipped = 0

    for r in records:
        gold = _parse_tag_list(r.get(gold_field, []))
        if not gold:          # 没有参考标签，跳过
            skipped += 1
            continue
        m = precision_recall_f1_per_record(r, pred_field, gold_field)
        precisions.append(m["precision"])
        recalls.append(m["recall"])
        f1s.append(m["f1"])

    n = len(precisions)
    return {
        "precision": sum(precisions) / n if n else 0.0,
        "recall":    sum(recalls)    / n if n else 0.0,
        "f1":        sum(f1s)        / n if n else 0.0,
        "total":     len(records),
        "evaluated": n,
        "skipped":   skipped,
    }


# --------------------------------------------------------------------------- #
# Top-K 命中率                                                                 #
# --------------------------------------------------------------------------- #

def compute_topk_accuracy(records: list, k: int = 1,
                          pred_field: str = "predicted_top3",
                          gold_field: str = "existing_attack_tags") -> float:
    """计算 Top-K Accuracy：预测的前 K 个中是否有至少一个命中 Gold"""
    if not records:
        return 0.0

    hits, total = 0, 0
    for r in records:
        gold = _parse_tag_list(r.get(gold_field, []))
        if not gold:
            continue
        pred_list = _parse_tag_sequence(r.get(pred_field, []))[:k]
        pred_set  = set(pred_list)
        if gold & pred_set:
            hits += 1
        total += 1

    return hits / total if total > 0 else 0.0


# --------------------------------------------------------------------------- #
# 修复行为准确率                                                               #
# --------------------------------------------------------------------------- #

def compute_repair_accuracy(records: list) -> dict:
    """
    评估修复行为（action）是否正确：
      - 若记录提供 expected_action / gold_action，则优先按人工期望动作评测
      - 否则按新修复动作做启发式判断
    （此为启发式规则，不是绝对真值，仅供参考）
    """
    correct, total = 0, 0
    for r in records:
        gold    = _parse_tag_list(r.get("existing_attack_tags", []))
        pred    = _parse_tag_list(r.get("predicted_top3", []))
        action  = r.get("action", "")

        expected = r.get("expected_action") or r.get("gold_action")
        if not expected:
            if not gold and pred:
                expected = "ADD_CANDIDATE"
            elif gold & pred:
                expected = "KEEP"
            elif gold and pred:
                expected = "REPLACE_SUSPECT"
            else:
                expected = "ABSTAIN"
        if action == expected:
            correct += 1
        total += 1

    return {"correct": correct, "total": total,
            "accuracy": correct / total if total else 0.0}


# --------------------------------------------------------------------------- #
# Abstain 统计                                                                 #
# --------------------------------------------------------------------------- #

def compute_abstain_stats(records: list) -> dict:
    total    = len(records)
    abstains = sum(1 for r in records if str(r.get("abstain", "False")).lower() == "true")
    return {"total": total, "abstain_count": abstains,
            "ratio": abstains / total if total else 0.0}


# --------------------------------------------------------------------------- #
# Confidence 分布                                                              #
# --------------------------------------------------------------------------- #

def compute_confidence_distribution(records: list, bins: int = 5) -> dict:
    """将置信度分箱，统计每箱的规则数量"""
    import math
    bucket_size = 1.0 / bins
    dist = {f"{i/bins:.1f}-{(i+1)/bins:.1f}": 0 for i in range(bins)}

    for r in records:
        try:
            c = float(r.get("confidence", 0.0))
        except (ValueError, TypeError):
            c = 0.0
        bucket_idx = min(int(c / bucket_size), bins - 1)
        key = f"{bucket_idx/bins:.1f}-{(bucket_idx+1)/bins:.1f}"
        dist[key] = dist.get(key, 0) + 1

    return dist


# --------------------------------------------------------------------------- #
# Silver Standard 过滤器                                                       #
# --------------------------------------------------------------------------- #

def filter_silver_standard(records: list, threshold: float = 0.85) -> list:
    """
    筛选出置信度 >= threshold 且有原始标签的规则，
    将其 existing_attack_tags 视为相对可靠的参考标签（Silver Standard）
    """
    silver = []
    for r in records:
        try:
            conf = float(r.get("confidence", 0.0))
        except (ValueError, TypeError):
            conf = 0.0
        gold = _parse_tag_list(r.get("existing_attack_tags", []))
        if conf >= threshold and gold:
            silver.append(r)
    return silver
