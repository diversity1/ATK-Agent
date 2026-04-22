import random

def drop_one_tag(rule_record: dict) -> dict:
    tags = rule_record.get("existing_attack_tags", [])
    if not tags:
        return rule_record
    new_tags = tags.copy()
    new_tags.pop(random.randint(0, len(new_tags)-1))
    rule_record["existing_attack_tags"] = new_tags
    return rule_record

def swap_with_wrong_technique(rule_record: dict, attack_index: dict) -> dict:
    tags = rule_record.get("existing_attack_tags", [])
    if not tags or not attack_index:
        return rule_record
    new_tags = tags.copy()
    idx = random.randint(0, len(new_tags)-1)
    all_keys = list(attack_index.keys())
    wrong = random.choice(all_keys)
    new_tags[idx] = wrong
    rule_record["existing_attack_tags"] = new_tags
    return rule_record

def coarsen_or_refine_tag(rule_record: dict, attack_index: dict) -> dict:
    # stub
    return rule_record

def remove_partial_multilabel(rule_record: dict) -> dict:
    # stub
    return rule_record

def build_noisy_dataset(rule_records: list, noise_type: str, ratio: float, attack_index: dict = None) -> list:
    noisy_records = []
    for rec in rule_records:
        rec_copy = rec.copy()
        if random.random() < ratio:
            if noise_type == "missing_tag":
                rec_copy = drop_one_tag(rec_copy)
            elif noise_type == "wrong_technique":
                rec_copy = swap_with_wrong_technique(rec_copy, attack_index)
        noisy_records.append(rec_copy)
    return noisy_records
