import json

def load_attack_raw(path: str) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def load_attack_index(path: str) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def attack_index_is_enriched(index: dict) -> bool:
    if not index:
        return False
    for doc in index.values():
        if doc.get("data_sources") or doc.get("detection"):
            return True
    return False

def _is_active_attack_object(obj: dict) -> bool:
    return not obj.get("x_mitre_deprecated", False) and not obj.get("revoked", False)

def _mitre_external_id(obj: dict) -> str:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""

def _mitre_url(obj: dict) -> str:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""

def _append_unique(items: list, value: str):
    if value and value not in items:
        items.append(value)

def build_attack_index_from_raw(raw_attack_path: str, save_path: str):
    raw = load_attack_raw(raw_attack_path)
    objects = raw.get("objects", [])
    objects_by_id = {obj.get("id"): obj for obj in objects if obj.get("id")}
    components_by_id = {
        obj["id"]: obj
        for obj in objects
        if obj.get("type") == "x-mitre-data-component" and _is_active_attack_object(obj)
    }
    analytics_by_id = {
        obj["id"]: obj
        for obj in objects
        if obj.get("type") == "x-mitre-analytic" and _is_active_attack_object(obj)
    }
    strategies_by_id = {
        obj["id"]: obj
        for obj in objects
        if obj.get("type") == "x-mitre-detection-strategy" and _is_active_attack_object(obj)
    }

    technique_to_strategy_ids = {}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "detects" or not _is_active_attack_object(obj):
            continue
        source_ref = obj.get("source_ref", "")
        target_ref = obj.get("target_ref", "")
        if source_ref in strategies_by_id and objects_by_id.get(target_ref, {}).get("type") == "attack-pattern":
            technique_to_strategy_ids.setdefault(target_ref, []).append(source_ref)

    index = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern" or not _is_active_attack_object(obj):
            continue

        tid = _mitre_external_id(obj)
        if not tid:
            continue

        tactics = [
            kp.get("phase_name")
            for kp in obj.get("kill_chain_phases", []) or []
            if kp.get("kill_chain_name") == "mitre-attack" and kp.get("phase_name")
        ]

        data_sources = []
        log_sources = []
        detection_parts = []

        for data_source in obj.get("x_mitre_data_sources", []) or []:
            _append_unique(data_sources, data_source)

        for strategy_id in technique_to_strategy_ids.get(obj.get("id"), []):
            strategy = strategies_by_id.get(strategy_id, {})
            _append_unique(detection_parts, strategy.get("name", ""))
            for analytic_id in strategy.get("x_mitre_analytic_refs", []) or []:
                analytic = analytics_by_id.get(analytic_id, {})
                _append_unique(detection_parts, analytic.get("description", ""))

                for log_ref in analytic.get("x_mitre_log_source_references", []) or []:
                    component = components_by_id.get(log_ref.get("x_mitre_data_component_ref"), {})
                    component_name = component.get("name", "")
                    _append_unique(data_sources, component_name)
                    log_sources.append({
                        "component": component_name,
                        "name": log_ref.get("name", ""),
                        "channel": log_ref.get("channel", ""),
                    })

        index[tid] = {
            "id": tid,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "detection": "\n\n".join(detection_parts),
            "tactics": tactics,
            "platforms": obj.get("x_mitre_platforms", []),
            "data_sources": data_sources,
            "log_sources": log_sources,
            "url": _mitre_url(obj),
            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
        }
                
    with open(save_path, 'w', encoding='utf-8') as f:
        json.dump(index, f, indent=2, ensure_ascii=False)
    return index
