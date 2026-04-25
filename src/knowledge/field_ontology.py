import re
from typing import Any, Dict, Iterable, List


FIELD_ONTOLOGY = {
    "commandline": {
        "normalized": "process.command_line",
        "observable_type": "command_line",
        "data_component": "Process Command",
    },
    "process.command_line": {
        "normalized": "process.command_line",
        "observable_type": "command_line",
        "data_component": "Process Command",
    },
    "processcommandline": {
        "normalized": "process.command_line",
        "observable_type": "command_line",
        "data_component": "Process Command",
    },
    "image": {
        "normalized": "process.executable",
        "observable_type": "process_image",
        "data_component": "Process Creation",
    },
    "process.executable": {
        "normalized": "process.executable",
        "observable_type": "process_image",
        "data_component": "Process Creation",
    },
    "process.name": {
        "normalized": "process.name",
        "observable_type": "process_name",
        "data_component": "Process Creation",
    },
    "processes.process_name": {
        "normalized": "process.name",
        "observable_type": "process_name",
        "data_component": "Process Creation",
    },
    "processes.process": {
        "normalized": "process.command_line",
        "observable_type": "command_line",
        "data_component": "Process Command",
    },
    "processes.process_path": {
        "normalized": "process.executable",
        "observable_type": "process_image",
        "data_component": "Process Creation",
    },
    "processname": {
        "normalized": "process.name",
        "observable_type": "process_name",
        "data_component": "Process Creation",
    },
    "filename": {
        "normalized": "process.name",
        "observable_type": "process_name",
        "data_component": "Process Creation",
    },
    "parentimage": {
        "normalized": "process.parent.executable",
        "observable_type": "parent_process",
        "data_component": "Process Creation",
    },
    "parentcommandline": {
        "normalized": "process.parent.command_line",
        "observable_type": "parent_command_line",
        "data_component": "Process Command",
    },
    "initiatingprocesscommandline": {
        "normalized": "process.parent.command_line",
        "observable_type": "parent_command_line",
        "data_component": "Process Command",
    },
    "initiatingprocessfilename": {
        "normalized": "process.parent.name",
        "observable_type": "parent_process",
        "data_component": "Process Creation",
    },
    "targetfilename": {
        "normalized": "file.path",
        "observable_type": "file_path",
        "data_component": "File Creation",
    },
    "file.path": {
        "normalized": "file.path",
        "observable_type": "file_path",
        "data_component": "File Creation",
    },
    "registrykey": {
        "normalized": "registry.key",
        "observable_type": "registry",
        "data_component": "Windows Registry Key Modification",
    },
    "targetobject": {
        "normalized": "registry.key",
        "observable_type": "registry",
        "data_component": "Windows Registry Key Modification",
    },
    "registry.path": {
        "normalized": "registry.key",
        "observable_type": "registry",
        "data_component": "Windows Registry Key Modification",
    },
    "eventid": {
        "normalized": "event.id",
        "observable_type": "event_id",
        "data_component": "",
    },
    "eventcode": {
        "normalized": "event.id",
        "observable_type": "event_id",
        "data_component": "",
    },
    "winlog.event_id": {
        "normalized": "event.id",
        "observable_type": "event_id",
        "data_component": "",
    },
    "destinationhostname": {
        "normalized": "destination.domain",
        "observable_type": "network",
        "data_component": "Network Connection Creation",
    },
    "destinationip": {
        "normalized": "destination.ip",
        "observable_type": "network",
        "data_component": "Network Connection Creation",
    },
    "destinationport": {
        "normalized": "destination.port",
        "observable_type": "network",
        "data_component": "Network Connection Creation",
    },
    "dest_port": {
        "normalized": "destination.port",
        "observable_type": "network",
        "data_component": "Network Connection Creation",
    },
    "queryname": {
        "normalized": "dns.question.name",
        "observable_type": "dns",
        "data_component": "DNS Query",
    },
    "dns.question.name": {
        "normalized": "dns.question.name",
        "observable_type": "dns",
        "data_component": "DNS Query",
    },
    "scriptblocktext": {
        "normalized": "script.content",
        "observable_type": "script_keyword",
        "data_component": "Script Execution",
    },
    "script.content": {
        "normalized": "script.content",
        "observable_type": "script_keyword",
        "data_component": "Script Execution",
    },
}


def split_field_modifiers(raw_field: str) -> tuple[str, List[str]]:
    parts = [part.strip() for part in str(raw_field or "").split("|") if part.strip()]
    if not parts:
        return "", []
    return parts[0], [part.lower() for part in parts[1:]]


def normalize_field_name(raw_field: str) -> Dict[str, str]:
    field, _ = split_field_modifiers(raw_field)
    key = str(field or "").strip().lower()
    info = FIELD_ONTOLOGY.get(key) or FIELD_ONTOLOGY.get(_field_key(field))
    if info:
        return {
            "field": field,
            "normalized_field": info["normalized"],
            "type": info["observable_type"],
            "data_component": info.get("data_component", ""),
        }

    lowered = field.lower()
    if "command" in lowered and "line" in lowered:
        return _fallback(field, "process.command_line", "command_line", "Process Command")
    if "parent" in lowered and ("image" in lowered or "process" in lowered):
        return _fallback(field, "process.parent.executable", "parent_process", "Process Creation")
    if "image" in lowered or lowered.endswith("process"):
        return _fallback(field, "process.executable", "process_image", "Process Creation")
    if "registry" in lowered or "reg" in lowered or "targetobject" in lowered:
        return _fallback(field, "registry.key", "registry", "Windows Registry Key Modification")
    if "dns" in lowered or "queryname" in lowered:
        return _fallback(field, "dns.question.name", "dns", "DNS Query")
    if "ip" in lowered or "port" in lowered or "destination" in lowered:
        return _fallback(field, lowered, "network", "Network Connection Creation")
    if "event" in lowered and ("id" in lowered or "code" in lowered):
        return _fallback(field, "event.id", "event_id", "")
    return _fallback(field, lowered or "unknown", "other", "")


def infer_operator(modifiers: Iterable[str], raw_value: Any = None, default: str = "equals") -> str:
    modifiers = {str(mod).lower() for mod in modifiers}
    if "contains" in modifiers:
        return "contains"
    if "startswith" in modifiers:
        return "startswith"
    if "endswith" in modifiers:
        return "endswith"
    if "re" in modifiers or "regex" in modifiers:
        return "regex"
    if "exists" in modifiers:
        return "exists"
    if "all" in modifiers:
        return "contains_all"

    value = str(raw_value or "")
    if "*" in value or "%" in value:
        return "wildcard"
    return default


def flatten_values(value: Any) -> List[Any]:
    if isinstance(value, list):
        flattened = []
        for item in value:
            flattened.extend(flatten_values(item))
        return flattened
    if isinstance(value, dict):
        flattened = []
        for item in value.values():
            flattened.extend(flatten_values(item))
        return flattened
    if value is None:
        return []
    return [value]


def clean_entity(value: Any) -> str:
    text = str(value or "").strip().strip('"').strip("'")
    text = text.replace("\\\\", "\\")
    text = re.sub(r"^[*%]+|[*%]+$", "", text)
    text = text.strip()
    if "\\" in text and not text.endswith("\\"):
        tail = text.rsplit("\\", 1)[-1]
        if "." in tail and len(tail) > 2:
            return tail
    return text


def make_observable(raw_field: str, value: Any, operator: str = "") -> Dict[str, Any]:
    field, modifiers = split_field_modifiers(raw_field)
    info = normalize_field_name(field)
    return {
        "field": field,
        "normalized_field": info["normalized_field"],
        "type": info["type"],
        "operator": operator or infer_operator(modifiers, value),
        "value": str(value),
        "data_component": info.get("data_component", ""),
    }


def _field_key(field: str) -> str:
    return re.sub(r"[\s_\-]+", "", str(field or "").strip().lower())


def _fallback(field: str, normalized: str, observable_type: str, data_component: str) -> Dict[str, str]:
    return {
        "field": field,
        "normalized_field": normalized,
        "type": observable_type,
        "data_component": data_component,
    }
