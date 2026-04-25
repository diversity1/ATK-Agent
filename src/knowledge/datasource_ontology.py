from typing import Dict, Iterable, List, Tuple

from knowledge.eventcode_mapping import lookup_eventcode


DATASOURCE_ONTOLOGY = {
    "sigma:product:windows": {
        "platforms": ["Windows"],
        "telemetry": [],
        "data_components": [],
        "hints": ["windows", "wineventlog"],
    },
    "sigma:product:linux": {
        "platforms": ["Linux"],
        "telemetry": [],
        "data_components": [],
        "hints": ["linux", "auditd", "syslog"],
    },
    "sigma:product:macos": {
        "platforms": ["macOS"],
        "telemetry": [],
        "data_components": [],
        "hints": ["macos", "esf"],
    },
    "sigma:category:process_creation": {
        "platforms": [],
        "telemetry": ["Process Creation"],
        "data_components": ["Process Creation", "Process Command"],
        "hints": ["process creation", "command execution", "process command"],
    },
    "sigma:category:process_access": {
        "platforms": [],
        "telemetry": ["Process Access"],
        "data_components": ["Process Access", "OS API Execution"],
        "hints": ["process access", "os api execution"],
    },
    "sigma:category:create_remote_thread": {
        "platforms": [],
        "telemetry": ["Create Remote Thread"],
        "data_components": ["Process Access", "OS API Execution"],
        "hints": ["create remote thread", "process injection"],
    },
    "sigma:category:network_connection": {
        "platforms": [],
        "telemetry": ["Network Connection"],
        "data_components": ["Network Connection Creation", "Network Traffic Flow"],
        "hints": ["network connection", "network traffic"],
    },
    "sigma:category:dns_query": {
        "platforms": [],
        "telemetry": ["DNS Query"],
        "data_components": ["DNS Query"],
        "hints": ["dns", "domain name"],
    },
    "sigma:category:image_load": {
        "platforms": [],
        "telemetry": ["Image Load"],
        "data_components": ["Module Load"],
        "hints": ["module load", "image load", "dll"],
    },
    "sigma:category:driver_load": {
        "platforms": [],
        "telemetry": ["Driver Load"],
        "data_components": ["Driver Load"],
        "hints": ["driver load", "driver", "module load"],
    },
    "sigma:category:pipe_created": {
        "platforms": [],
        "telemetry": ["Named Pipe"],
        "data_components": ["Named Pipe Metadata"],
        "hints": ["named pipe", "pipe"],
    },
    "sigma:category:wmi_event": {
        "platforms": [],
        "telemetry": ["WMI Event"],
        "data_components": ["WMI Creation"],
        "hints": ["wmi", "windows management instrumentation"],
    },
    "sigma:category:registry_add": {
        "platforms": [],
        "telemetry": ["Registry Modification"],
        "data_components": ["Windows Registry Key Modification"],
        "hints": ["windows registry key modification", "registry"],
    },
    "sigma:category:registry_set": {
        "platforms": [],
        "telemetry": ["Registry Modification"],
        "data_components": ["Windows Registry Key Modification"],
        "hints": ["windows registry key modification", "registry"],
    },
    "sigma:service:powershell": {
        "platforms": ["Windows"],
        "telemetry": ["Script Execution"],
        "data_components": ["Script Execution", "Command Execution"],
        "hints": ["powershell", "script execution", "4104"],
    },
    "sigma:service:security": {
        "platforms": ["Windows"],
        "telemetry": ["Windows Security Log"],
        "data_components": ["Logon Session Creation", "User Account Authentication"],
        "hints": ["wineventlog:security", "logon session", "user account authentication"],
    },
    "sigma:service:sysmon": {
        "platforms": ["Windows"],
        "telemetry": [],
        "data_components": [],
        "hints": ["sysmon"],
    },
    "splunk:sourcetype:xmlwineventlog:microsoft-windows-sysmon/operational": {
        "platforms": ["Windows"],
        "telemetry": [],
        "data_components": [],
        "hints": ["sysmon", "wineventlog"],
    },
    "splunk:sourcetype:wineventlog:security": {
        "platforms": ["Windows"],
        "telemetry": ["Windows Security Log"],
        "data_components": ["Logon Session Creation", "User Account Authentication"],
        "hints": ["wineventlog:security", "windows security"],
    },
}


def sigma_context(product: str = "", category: str = "", service: str = "") -> Dict[str, List[str]]:
    keys = []
    if product:
        keys.append(f"sigma:product:{_normalize_key(product)}")
    if category:
        keys.append(f"sigma:category:{_normalize_key(category)}")
    if service:
        keys.append(f"sigma:service:{_normalize_key(service)}")
    return merge_contexts(DATASOURCE_ONTOLOGY.get(key, {}) for key in keys)


def splunk_context(
    event_codes: Iterable[str] = (),
    sourcetypes: Iterable[str] = (),
    indexes: Iterable[str] = (),
) -> Dict[str, List[str]]:
    contexts = []
    for sourcetype in sourcetypes:
        key = f"splunk:sourcetype:{str(sourcetype).strip().lower()}"
        contexts.append(DATASOURCE_ONTOLOGY.get(key, {}))

    for event_code in event_codes:
        contexts.append(lookup_eventcode(str(event_code)))

    for index in indexes:
        normalized = str(index).lower()
        if "winevent" in normalized or "windows" in normalized or "sysmon" in normalized:
            contexts.append({"platforms": ["Windows"], "hints": ["windows", "wineventlog"]})
        elif "linux" in normalized or "audit" in normalized:
            contexts.append({"platforms": ["Linux"], "hints": ["linux", "auditd"]})

    return merge_contexts(contexts)


def context_to_hints(context: Dict[str, List[str]]) -> List[Tuple[str, float]]:
    hints = []
    for telemetry in context.get("telemetry", []):
        hints.append((telemetry, 0.45))
    for component in context.get("data_components", []):
        hints.append((component, 0.35))
    for platform in context.get("platforms", []):
        hints.append((platform, 0.20))
    for hint in context.get("hints", []):
        hints.append((hint, 0.25))
    return _dedupe_hints(hints)


def build_ir_hints(rule_ir) -> List[Tuple[str, float]]:
    if not rule_ir:
        return []

    hints = []
    for telemetry in getattr(rule_ir, "telemetry", []) or []:
        hints.append((telemetry, 0.45))
    for component in getattr(rule_ir, "data_components", []) or []:
        hints.append((component, 0.35))
    for platform in getattr(rule_ir, "platforms", []) or []:
        hints.append((platform, 0.20))
    for observable in getattr(rule_ir, "observables", []) or []:
        data_component = observable.get("data_component")
        value = observable.get("value")
        if data_component:
            hints.append((data_component, 0.30))
        if observable.get("type") == "event_id" and value:
            hints.append((str(value), 0.12))
    return _dedupe_hints(hints)


def merge_contexts(contexts: Iterable[Dict]) -> Dict[str, List[str]]:
    merged = {
        "platforms": [],
        "telemetry": [],
        "data_components": [],
        "hints": [],
    }
    for context in contexts:
        if not context:
            continue
        for key in merged:
            merged[key].extend(context.get(key, []) or [])
    return {key: _dedupe_values(values) for key, values in merged.items()}


def _normalize_key(value: str) -> str:
    return str(value or "").strip().lower().replace("-", "_")


def _dedupe_values(values: Iterable[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        text = str(value or "").strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            result.append(text)
    return result


def _dedupe_hints(hints: Iterable[Tuple[str, float]]) -> List[Tuple[str, float]]:
    deduped = {}
    for term, weight in hints:
        key = str(term or "").strip().lower()
        if key:
            deduped[key] = max(float(weight), deduped.get(key, 0.0))
    return list(deduped.items())
