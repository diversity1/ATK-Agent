from typing import Any, Dict, List

from core.schemas import DetectionRuleIR
from knowledge.datasource_ontology import merge_contexts, sigma_context
from knowledge.eventcode_mapping import lookup_eventcode
from knowledge.field_ontology import clean_entity, flatten_values, make_observable
from parsers.base import build_normalized_text, derive_legacy_category, extract_attack_tags


CONTROL_FIELDS = {"condition", "timeframe", "fields", "falsepositives"}


class SigmaAdapter:
    source_type = "sigma"

    def parse(self, raw_rule: Dict[str, Any], file_path: str = "") -> DetectionRuleIR:
        rule_dict = raw_rule or {}
        file_path = file_path or rule_dict.get("_source_file", "")

        logsource = rule_dict.get("logsource", {}) or {}
        product = str(logsource.get("product", "") or "")
        category = str(logsource.get("category", "") or "")
        service = str(logsource.get("service", "") or "")

        raw_tags = rule_dict.get("tags", []) or []
        detection = rule_dict.get("detection", {}) or {}
        observables = _extract_observables_from_detection(detection)
        entities = _extract_entities(observables)

        event_contexts = []
        for observable in observables:
            if observable.get("type") == "event_id":
                event_contexts.append(lookup_eventcode(str(observable.get("value", ""))))

        source_context = merge_contexts([
            sigma_context(product, category, service),
            *event_contexts,
        ])
        data_components = _dedupe([
            *source_context.get("data_components", []),
            *(obs.get("data_component", "") for obs in observables),
        ])
        telemetry = source_context.get("telemetry", [])
        platforms = source_context.get("platforms", [])

        title = str(rule_dict.get("title", "") or "")
        description = str(rule_dict.get("description", "") or "")
        behavior_summary = _build_behavior_summary(title, telemetry, entities)

        rule_ir = DetectionRuleIR(
            rule_id=str(rule_dict.get("id", "unknown_id") or "unknown_id"),
            source_type=self.source_type,
            source_file=file_path,
            query_language="sigma_yaml",
            title=title,
            description=description,
            severity=str(rule_dict.get("level", "") or ""),
            status=str(rule_dict.get("status", "") or ""),
            product=product,
            category=category or derive_legacy_category(telemetry),
            service=service,
            platforms=platforms,
            telemetry=telemetry,
            data_components=data_components,
            observables=observables,
            entities=entities,
            detection_logic={
                "type": "sigma_detection",
                "condition": detection.get("condition", "") if isinstance(detection, dict) else "",
                "raw": detection,
            },
            raw_tags=raw_tags if isinstance(raw_tags, list) else [str(raw_tags)],
            existing_attack_tags=extract_attack_tags(raw_tags),
            behavior_summary=behavior_summary,
        )
        rule_ir.normalized_text = build_normalized_text(rule_ir)
        return rule_ir


def _extract_observables_from_detection(detection: Any) -> List[Dict[str, Any]]:
    observables = []

    def walk(obj: Any):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if str(key).lower() in CONTROL_FIELDS:
                    continue
                if isinstance(value, dict):
                    walk(value)
                elif isinstance(value, list) and any(isinstance(item, dict) for item in value):
                    for item in value:
                        walk(item)
                else:
                    for flat_value in flatten_values(value):
                        observables.append(make_observable(str(key), flat_value))
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(detection)
    return _dedupe_observables(observables)


def _extract_entities(observables: List[Dict[str, Any]]) -> List[str]:
    entities = []
    for observable in observables:
        value = clean_entity(observable.get("value", ""))
        if len(value) >= 2 and value.lower() not in {"true", "false", "none", "null"}:
            entities.append(value)
    return _dedupe(entities)[:80]


def _build_behavior_summary(title: str, telemetry: List[str], entities: List[str]) -> str:
    parts = []
    if title:
        parts.append(title)
    if telemetry:
        parts.append("telemetry=" + ", ".join(telemetry[:3]))
    if entities:
        parts.append("indicators=" + " | ".join(entities[:12]))
    return "; ".join(parts)


def _dedupe(values) -> List[str]:
    seen = set()
    result = []
    for value in values:
        text = str(value or "").strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            result.append(text)
    return result


def _dedupe_observables(observables: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    result = []
    for observable in observables:
        key = (
            observable.get("normalized_field", "").lower(),
            observable.get("operator", "").lower(),
            str(observable.get("value", "")).lower(),
        )
        if key not in seen:
            seen.add(key)
            result.append(observable)
    return result

