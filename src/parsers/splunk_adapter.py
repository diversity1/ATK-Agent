import re
from typing import Any, Dict, List, Tuple

from core.schemas import DetectionRuleIR
from knowledge.datasource_ontology import splunk_context
from knowledge.field_ontology import clean_entity, make_observable
from parsers.base import build_normalized_text, derive_legacy_category, extract_attack_tags


ASSIGNMENT_RE = re.compile(
    r"(?<![<>=!])\b([A-Za-z_][\w.:-]*)\s*(=|!=)\s*(\"[^\"]*\"|'[^']*'|[^\s|]+)",
    re.IGNORECASE,
)
IN_RE = re.compile(r"\b([A-Za-z_][\w.:-]*)\s+IN\s*\(([^)]*)\)", re.IGNORECASE)


class SplunkAdapter:
    source_type = "splunk"

    def parse(self, raw_rule: Any, file_path: str = "") -> DetectionRuleIR:
        rule_dict = raw_rule if isinstance(raw_rule, dict) else {"search": str(raw_rule or "")}
        file_path = file_path or rule_dict.get("_source_file", "")

        search = _extract_search(rule_dict)
        assignments = _extract_assignments(search)
        observables = _assignments_to_observables(assignments)
        entities = _extract_entities(observables)

        indexes = _values_for(assignments, "index")
        sourcetypes = _values_for(assignments, "sourcetype")
        event_codes = [
            *(_values_for(assignments, "EventCode")),
            *(_values_for(assignments, "EventID")),
            *(_values_for(assignments, "event_id")),
            *(_values_for(assignments, "winlog.event_id")),
        ]
        source_context = splunk_context(event_codes, sourcetypes, indexes)

        data_components = _dedupe([
            *source_context.get("data_components", []),
            *(obs.get("data_component", "") for obs in observables),
        ])
        telemetry = source_context.get("telemetry", [])
        platforms = source_context.get("platforms", [])

        title = str(rule_dict.get("name") or rule_dict.get("title") or rule_dict.get("rule_name") or "")
        description = str(rule_dict.get("description", "") or "")
        raw_tags = _collect_raw_tags(rule_dict)
        behavior_summary = _build_behavior_summary(title, telemetry, entities, search)

        rule_ir = DetectionRuleIR(
            rule_id=str(rule_dict.get("id") or rule_dict.get("rule_id") or title or "unknown_id"),
            source_type=self.source_type,
            source_file=file_path,
            query_language="spl",
            title=title,
            description=description,
            severity=str(rule_dict.get("severity", "") or ""),
            status=str(rule_dict.get("status", "") or ""),
            product="windows" if "Windows" in platforms else "splunk",
            category=derive_legacy_category(telemetry),
            service=sourcetypes[0] if sourcetypes else "",
            platforms=platforms,
            telemetry=telemetry,
            data_components=data_components,
            observables=observables,
            entities=entities,
            detection_logic={
                "type": "spl_search",
                "search": search,
                "assignments": [
                    {"field": field, "operator": operator, "value": value}
                    for field, operator, value in assignments
                ],
            },
            raw_tags=raw_tags,
            existing_attack_tags=extract_attack_tags(raw_tags),
            behavior_summary=behavior_summary,
        )
        rule_ir.normalized_text = build_normalized_text(rule_ir)
        return rule_ir


def _extract_search(rule_dict: Dict[str, Any]) -> str:
    for key in ("search", "query", "spl", "rule", "detection"):
        value = rule_dict.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _extract_assignments(search: str) -> List[Tuple[str, str, str]]:
    assignments = []
    occupied = []

    for match in IN_RE.finditer(search or ""):
        field = match.group(1)
        occupied.append(match.span())
        for value in _split_in_values(match.group(2)):
            assignments.append((field, "in", value))

    for match in ASSIGNMENT_RE.finditer(search or ""):
        if any(_overlaps(match.span(), span) for span in occupied):
            continue
        field, operator, value = match.group(1), match.group(2), match.group(3)
        assignments.append((field, operator, _strip_quotes(value)))

    return _dedupe_assignments(assignments)


def _assignments_to_observables(assignments: List[Tuple[str, str, str]]) -> List[Dict[str, Any]]:
    observables = []
    for field, operator, value in assignments:
        if field.lower() in {"index", "sourcetype", "source"}:
            continue
        normalized_operator = "not_equals" if operator == "!=" else operator
        if operator == "=" and ("*" in value or "%" in value):
            normalized_operator = "wildcard"
        observables.append(make_observable(field, value, normalized_operator))
    return observables


def _collect_raw_tags(rule_dict: Dict[str, Any]) -> List[str]:
    tags = []
    for key in ("tags", "tag", "mitre_attack_id", "attack", "techniques"):
        value = rule_dict.get(key)
        tags.extend(_flatten_tag_value(value))

    annotations = rule_dict.get("annotations", {})
    if isinstance(annotations, dict):
        for key in ("mitre_attack", "mitre_attack_id", "attack", "techniques"):
            tags.extend(_flatten_tag_value(annotations.get(key)))
    return _dedupe(tags)


def _flatten_tag_value(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        tags = []
        for item in value:
            tags.extend(_flatten_tag_value(item))
        return tags
    if isinstance(value, dict):
        tags = []
        for item in value.values():
            tags.extend(_flatten_tag_value(item))
        return tags
    return [str(value)]


def _values_for(assignments: List[Tuple[str, str, str]], field_name: str) -> List[str]:
    expected = field_name.lower()
    return _dedupe([
        _strip_quotes(value)
        for field, _, value in assignments
        if field.lower() == expected
    ])


def _extract_entities(observables: List[Dict[str, Any]]) -> List[str]:
    entities = []
    for observable in observables:
        value = clean_entity(observable.get("value", ""))
        if len(value) >= 2 and value.lower() not in {"true", "false", "none", "null"}:
            entities.append(value)
    return _dedupe(entities)[:80]


def _build_behavior_summary(title: str, telemetry: List[str], entities: List[str], search: str) -> str:
    parts = []
    if title:
        parts.append(title)
    if telemetry:
        parts.append("telemetry=" + ", ".join(telemetry[:3]))
    if entities:
        parts.append("indicators=" + " | ".join(entities[:12]))
    if not parts and search:
        parts.append(search[:180])
    return "; ".join(parts)


def _split_in_values(value_block: str) -> List[str]:
    values = []
    for value in re.split(r"\s*,\s*", value_block or ""):
        value = _strip_quotes(value)
        if value:
            values.append(value)
    return values


def _strip_quotes(value: str) -> str:
    return str(value or "").strip().strip('"').strip("'")


def _overlaps(span_a, span_b) -> bool:
    return span_a[0] < span_b[1] and span_b[0] < span_a[1]


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


def _dedupe_assignments(assignments: List[Tuple[str, str, str]]) -> List[Tuple[str, str, str]]:
    seen = set()
    result = []
    for field, operator, value in assignments:
        key = (field.lower(), operator.lower(), str(value).lower())
        if key not in seen:
            seen.add(key)
            result.append((field, operator, value))
    return result

