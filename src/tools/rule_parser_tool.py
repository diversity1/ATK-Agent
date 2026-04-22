import yaml
from core.schemas import ParsedRule
from tools.tag_validator_tool import is_valid_attack_tag, normalize_attack_tag

def load_rule(path: str) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        if path.endswith('.yml') or path.endswith('.yaml'):
            return yaml.safe_load(f)
        return {}

def extract_attack_tags(tags: list) -> list:
    if not tags:
        return []
    result = []
    for t in tags:
        if is_valid_attack_tag(t):
            result.append(normalize_attack_tag(t))
    return result

def build_normalized_rule_text(parsed_fields: dict) -> str:
    parts = []
    if parsed_fields.get("title"):
        parts.append(f"Title: {parsed_fields['title']}")
    if parsed_fields.get("description"):
        parts.append(f"Description: {parsed_fields['description']}")
    if parsed_fields.get("product"):
        parts.append(f"Product: {parsed_fields['product']}")
    if parsed_fields.get("category"):
        parts.append(f"Category: {parsed_fields['category']}")
    if parsed_fields.get("detection_text"):
        parts.append(f"Detection: {parsed_fields['detection_text']}")
    return "\n".join(parts)

def parse_sigma_rule(rule_dict: dict, file_path: str = "") -> ParsedRule:
    rule_id = rule_dict.get("id", "unknown_id")
    title = rule_dict.get("title", "")
    description = rule_dict.get("description", "")
    logsource = rule_dict.get("logsource", {})
    product = logsource.get("product", "")
    category = logsource.get("category", "")
    service = logsource.get("service", "")
    
    raw_tags = rule_dict.get("tags", [])
    existing_attack_tags = extract_attack_tags(raw_tags)
    
    detection = rule_dict.get("detection", {})
    detection_text = str(detection)
    
    parsed_fields = {
        "title": title,
        "description": description,
        "product": product,
        "category": category,
        "detection_text": detection_text
    }
    normalized_rule_text = build_normalized_rule_text(parsed_fields)
    
    return ParsedRule(
        rule_id=rule_id,
        source_type="sigma",
        source_file=file_path,
        title=title,
        description=description,
        product=product,
        category=category,
        service=service,
        detection_text=detection_text,
        raw_tags=raw_tags,
        existing_attack_tags=existing_attack_tags,
        normalized_rule_text=normalized_rule_text
    )

def parse_splunk_rule(rule_dict: dict, file_path: str = "") -> ParsedRule:
    # Minimal stub for Splunk rules
    title = rule_dict.get("name", "")
    description = rule_dict.get("description", "")
    rule_id = rule_dict.get("id", "unknown_id")
    raw_tags = rule_dict.get("tags", {}).get("mitre_attack_id", [])
    existing_attack_tags = extract_attack_tags(raw_tags)
    
    detection_text = rule_dict.get("search", "")
    
    parsed_fields = {
        "title": title,
        "description": description,
        "detection_text": detection_text
    }
    normalized_rule_text = build_normalized_rule_text(parsed_fields)
    
    return ParsedRule(
        rule_id=rule_id,
        source_type="splunk",
        source_file=file_path,
        title=title,
        description=description,
        product="splunk",
        category="",
        service="",
        detection_text=detection_text,
        raw_tags=raw_tags if isinstance(raw_tags, list) else [raw_tags],
        existing_attack_tags=existing_attack_tags,
        normalized_rule_text=normalized_rule_text
    )
