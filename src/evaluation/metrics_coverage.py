"""
metrics_coverage.py
覆盖率层面的评测指标（全部真实实现）

评估维度：
  - Jaccard 相似度（集合重叠度）
  - 覆盖缺口 delta（缺少哪些 / 多出哪些标签）
  - 修复前后的覆盖失真恢复率
"""

from typing import Set, List, Dict


def jaccard_coverage_similarity(reference: set, compared: set) -> float:
    """
    Jaccard 相似度：|A∩B| / |A∪B|
    衡量两组标签集合之间的相似程度，范围 [0, 1]
    """
    if not reference and not compared:
        return 1.0
    if not reference or not compared:
        return 0.0
    intersection = len(reference.intersection(compared))
    union        = len(reference.union(compared))
    return intersection / union


def coverage_delta(reference: set, compared: set) -> dict:
    """
    覆盖缺口分析：
      - missing: reference 中有，但 compared 中没有的（漏报）
      - extra:   compared 中有，但 reference 中没有的（多报）
    """
    return {
        "missing":        sorted(reference - compared),
        "extra":          sorted(compared  - reference),
        "missing_count":  len(reference - compared),
        "extra_count":    len(compared  - reference),
        "overlap_count":  len(reference & compared),
    }


def gap_detection_stats(records: list,
                        gold_field: str  = "existing_attack_tags",
                        pred_field: str  = "predicted_top3") -> dict:
    """
    对批量规则汇总计算：
      - 平均漏报数 / 规则
      - 平均多报数 / 规则
      - 完全命中率（predicted 完全包含 gold 的规则比例）
    """
    from evaluation.metrics_rule_level import _parse_tag_list

    total_missing, total_extra, total_perfect = 0, 0, 0
    n = len(records)
    if n == 0:
        return {}

    for r in records:
        gold = _parse_tag_list(r.get(gold_field, []))
        pred = _parse_tag_list(r.get(pred_field, []))
        delta = coverage_delta(gold, pred)
        total_missing += delta["missing_count"]
        total_extra   += delta["extra_count"]
        if delta["missing_count"] == 0:
            total_perfect += 1

    return {
        "avg_missing_per_rule": total_missing / n,
        "avg_extra_per_rule":   total_extra   / n,
        "perfect_coverage_rate": total_perfect / n,
        "total_rules": n,
    }


def coverage_distortion_reduction(noisy_tags: set,
                                  repaired_tags: set,
                                  reference_tags: set) -> float:
    """
    覆盖失真恢复率 (Coverage Distortion Reduction, CDR)。

    CDR = (D_noisy - D_repaired) / D_noisy
    其中 D = 1 - Jaccard(prediction, reference)

    CDR > 0 表示修复后更接近参考标签（有改善）
    CDR < 0 表示修复后反而更差
    CDR = 1 表示完美恢复
    """
    d_noisy    = 1.0 - jaccard_coverage_similarity(reference_tags, noisy_tags)
    d_repaired = 1.0 - jaccard_coverage_similarity(reference_tags, repaired_tags)

    if d_noisy == 0.0:
        return 1.0   # 本来就完美，返回 1

    return (d_noisy - d_repaired) / d_noisy


def batch_cdr_stats(records: list,
                    noisy_field:    str = "existing_attack_tags",
                    repaired_field: str = "final_tags",
                    reference_field: str = "predicted_top3") -> dict:
    """
    批量计算 CDR，并汇总统计：
    - mean_cdr: 平均恢复率
    - improved_ratio: 修复后更好的规则比例
    - degraded_ratio: 修复后更差的规则比例
    """
    from evaluation.metrics_rule_level import _parse_tag_list

    cdrs = []
    for r in records:
        noisy    = _parse_tag_list(r.get(noisy_field, []))
        repaired = _parse_tag_list(r.get(repaired_field, []))
        ref      = _parse_tag_list(r.get(reference_field, []))
        if not ref:
            continue
        cdr = coverage_distortion_reduction(noisy, repaired, ref)
        cdrs.append(cdr)

    if not cdrs:
        return {"mean_cdr": 0.0, "improved_ratio": 0.0,
                "degraded_ratio": 0.0, "total": 0}

    return {
        "mean_cdr":        sum(cdrs) / len(cdrs),
        "improved_ratio":  sum(1 for c in cdrs if c > 0)  / len(cdrs),
        "degraded_ratio":  sum(1 for c in cdrs if c < 0)  / len(cdrs),
        "perfect_ratio":   sum(1 for c in cdrs if c >= 1) / len(cdrs),
        "total":           len(cdrs),
    }
