def compute_topk_accuracy(records: list, k: int = 1) -> float:
    # mock
    return 0.0

def compute_repair_accuracy(records: list) -> float:
    # mock
    return 0.0

def compute_action_accuracy(records: list) -> float:
    # mock
    return 0.0

def compute_abstain_stats(records: list) -> dict:
    total = len(records)
    abstains = sum(1 for r in records if r.get("abstain", False))
    return {"total": total, "abstain_count": abstains, "ratio": abstains/total if total else 0}

def compute_macro_f1(records: list) -> float:
    # mock
    return 0.0
