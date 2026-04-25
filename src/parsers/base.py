from typing import Any, Dict, List, Protocol

from core.schemas import DetectionRuleIR, ParsedRule
from tools.tag_validator_tool import is_valid_attack_tag, normalize_attack_tag


class RuleAdapter(Protocol):
    source_type: str

    def parse(self, raw_rule: Any, file_path: str = "") -> DetectionRuleIR:
        ...


def extract_attack_tags(raw_tags: Any) -> List[str]:
    tags = _coerce_tag_list(raw_tags)
    result = []
    for tag in tags:
        if is_valid_attack_tag(str(tag)):
            result.append(normalize_attack_tag(str(tag)))
    return _dedupe(result)


def ir_to_parsed_rule(rule_ir: DetectionRuleIR) -> ParsedRule:
    detection_text = rule_ir.behavior_summary
    if not detection_text:
        detection_text = "Detection indicators: " + " | ".join(rule_ir.entities[:30])

    return ParsedRule(
        rule_id=rule_ir.rule_id,
        source_type=rule_ir.source_type,
        source_file=rule_ir.source_file,
        title=rule_ir.title,
        description=rule_ir.description,
        product=rule_ir.product,
        category=rule_ir.category,
        service=rule_ir.service,
        detection_text=detection_text,
        raw_tags=rule_ir.raw_tags,
        existing_attack_tags=rule_ir.existing_attack_tags,
        normalized_rule_text=rule_ir.normalized_text,
        query_language=rule_ir.query_language,
        platforms=rule_ir.platforms,
        telemetry=rule_ir.telemetry,
        data_components=rule_ir.data_components,
        observables=rule_ir.observables,
        entities=rule_ir.entities,
        detection_logic=rule_ir.detection_logic,
        behavior_summary=rule_ir.behavior_summary,
        rule_ir=rule_ir,
    )


def build_normalized_text(rule_ir: DetectionRuleIR) -> str:
    parts = []
    if rule_ir.title:
        parts.append(f"Rule: {rule_ir.title}.")
    if rule_ir.description:
        parts.append(f"Description: {rule_ir.description[:400]}.")
    if rule_ir.platforms:
        parts.append(f"Platforms: {', '.join(rule_ir.platforms)}.")
    if rule_ir.telemetry:
        parts.append(f"Telemetry: {', '.join(rule_ir.telemetry)}.")
    if rule_ir.data_components:
        parts.append(f"Data Components: {', '.join(rule_ir.data_components)}.")
    if rule_ir.behavior_summary:
        parts.append(f"Behavior: {rule_ir.behavior_summary}.")
    if rule_ir.entities:
        parts.append("Detection indicators: " + " | ".join(rule_ir.entities[:40]) + ".")

    observable_text = []
    for observable in rule_ir.observables[:40]:
        field = observable.get("normalized_field") or observable.get("field") or ""
        operator = observable.get("operator") or ""
        value = observable.get("value") or ""
        if field and value:
            observable_text.append(f"{field} {operator} {value}".strip())
    if observable_text:
        parts.append("Observables: " + " | ".join(observable_text) + ".")
    return " ".join(parts)


def derive_legacy_category(telemetry: List[str]) -> str:
    if not telemetry:
        return ""
    first = telemetry[0].strip().lower()
    return first.replace(" ", "_").replace("-", "_")


def _coerce_tag_list(raw_tags: Any) -> List[str]:
    if raw_tags is None:
        return []
    if isinstance(raw_tags, str):
        return [raw_tags]
    if isinstance(raw_tags, list):
        return [str(tag) for tag in raw_tags]
    if isinstance(raw_tags, dict):
        tags = []
        for value in raw_tags.values():
            tags.extend(_coerce_tag_list(value))
        return tags
    return [str(raw_tags)]


def _dedupe(values: List[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        text = str(value or "").strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            result.append(text)
    return result

