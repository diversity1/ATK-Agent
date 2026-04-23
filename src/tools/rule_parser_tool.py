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


def _extract_strings_from_obj(obj, depth: int = 0) -> list:
    """递归提取任意嵌套结构中的所有字符串值（忽略键名噪声）。"""
    if depth > 6:
        return []
    results = []
    if isinstance(obj, str):
        # 过滤掉无意义的极短字符串或纯布尔关键字
        stripped = obj.strip()
        if len(stripped) >= 3 and stripped.lower() not in ("null", "true", "false", "none"):
            results.append(stripped)
    elif isinstance(obj, list):
        for item in obj:
            results.extend(_extract_strings_from_obj(item, depth + 1))
    elif isinstance(obj, dict):
        for key, val in obj.items():
            # 跳过控制字段 (condition, timeframe 等)
            if key.lower() in ("condition", "timeframe", "fields"):
                continue
            results.extend(_extract_strings_from_obj(val, depth + 1))
    elif obj is not None:
        results.append(str(obj))
    return results


def _extract_detection_keywords(detection: dict) -> str:
    """
    将 Sigma detection 块转为对 RAG embedding 友好的自然语言短句。

    示例输入:
        {'selection': {'EventID': 4624, 'CommandLine|contains': ['mimikatz', 'sekurlsa']},
         'condition': 'selection'}

    输出:
        "Detection indicators: 4624 mimikatz sekurlsa"
    """
    if not detection or not isinstance(detection, dict):
        return ""

    raw_vals = _extract_strings_from_obj(detection)
    # 去重，保留顺序
    seen = set()
    unique_vals = []
    for v in raw_vals:
        key = v.lower()
        if key not in seen:
            seen.add(key)
            unique_vals.append(v)

    # 最多保留 30 个关键词，避免超出 embedding 最大 token
    unique_vals = unique_vals[:30]
    if not unique_vals:
        return ""
    return "Detection indicators: " + " | ".join(unique_vals)


def build_normalized_rule_text(rule_dict: dict) -> str:
    """
    将结构化 Sigma 规则转为语义丰富的自然语言查询文本，供 RAG 编码使用。

    构成：
      Rule: <title>.
      Description: <description>.
      Log Source: product=<product>, category=<category>, service=<service>.
      Detection indicators: <递归提取的检测关键词>.
      Existing Tags: <已有标签>.
    """
    parts = []

    title = rule_dict.get("title", "").strip()
    if title:
        parts.append(f"Rule: {title}.")

    description = str(rule_dict.get("description", "") or "").strip()
    if description:
        # 截断过长描述
        parts.append(f"Description: {description[:300]}.")

    logsource = rule_dict.get("logsource", {}) or {}
    ls_parts = []
    for field in ("product", "category", "service"):
        val = logsource.get(field, "")
        if val:
            ls_parts.append(f"{field}={val}")
    if ls_parts:
        parts.append(f"Log Source: {', '.join(ls_parts)}.")

    detection = rule_dict.get("detection", {})
    det_text = _extract_detection_keywords(detection)
    if det_text:
        parts.append(det_text + ".")

    # 把已有的 ATT&CK 标签作为语义提示（加权）
    return " ".join(parts)


def parse_sigma_rule(rule_dict: dict, file_path: str = "") -> ParsedRule:
    rule_id     = rule_dict.get("id", "unknown_id")
    title       = rule_dict.get("title", "")
    description = str(rule_dict.get("description", "") or "")
    logsource   = rule_dict.get("logsource", {}) or {}
    product     = logsource.get("product", "")
    category    = logsource.get("category", "")
    service     = logsource.get("service", "")

    raw_tags            = rule_dict.get("tags", []) or []
    existing_attack_tags = extract_attack_tags(raw_tags)

    detection      = rule_dict.get("detection", {})
    detection_text = _extract_detection_keywords(detection)   # 使用富文本而非 str(dict)

    normalized_rule_text = build_normalized_rule_text(rule_dict)

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
