def is_valid_attack_tag(tag: str) -> bool:
    tag = tag.upper().strip()
    if tag.startswith("ATTACK."):
        tag = tag[7:]
    return tag.startswith("T") and len(tag) >= 5 and tag[1:5].isdigit()

def normalize_attack_tag(tag: str) -> str:
    tag = tag.upper().strip()
    if tag.startswith("ATTACK."):
        tag = tag[7:]
    return tag

def check_parent_child_relation(tag_a: str, tag_b: str) -> bool:
    # A is parent of B if A is TXXXX and B is TXXXX.XXX
    if not is_valid_attack_tag(tag_a) or not is_valid_attack_tag(tag_b):
        return False
    a = normalize_attack_tag(tag_a)
    b = normalize_attack_tag(tag_b)
    if len(a) == 5 and len(b) > 5 and b.startswith(a + "."):
        return True
    return False

def compare_existing_and_predicted(existing_tags: list, predicted_topk: list) -> dict:
    existing = set(normalize_attack_tag(t) for t in existing_tags if is_valid_attack_tag(t))
    predicted = set(predicted_topk)
    
    exact_matches = existing.intersection(predicted)
    missing_in_predicted = existing - predicted
    new_in_predicted = predicted - existing
    
    parent_child_matches = []
    for ext in existing:
        for pred in predicted:
            if check_parent_child_relation(ext, pred) or check_parent_child_relation(pred, ext):
                parent_child_matches.append((ext, pred))

    return {
        "exact_matches": list(exact_matches),
        "missing_in_predicted": list(missing_in_predicted),
        "new_in_predicted": list(new_in_predicted),
        "parent_child_matches": parent_child_matches
    }

def compute_mismatch_score(existing_tags: list, predicted_topk: list) -> float:
    comp = compare_existing_and_predicted(existing_tags, predicted_topk)
    existing_len = len([t for t in existing_tags if is_valid_attack_tag(t)])
    if existing_len == 0:
        return 1.0 if len(predicted_topk) > 0 else 0.0
    
    matched = len(comp["exact_matches"]) + (0.5 * len(comp["parent_child_matches"]))
    return max(0.0, 1.0 - (matched / existing_len))
