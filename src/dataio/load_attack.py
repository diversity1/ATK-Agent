import json

def load_attack_raw(path: str) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def load_attack_index(path: str) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def build_attack_index_from_raw(raw_attack_path: str, save_path: str):
    # Simplified logic to just demonstrate
    raw = load_attack_raw(raw_attack_path)
    index = {}
    
    objects = raw.get("objects", [])
    for obj in objects:
        if obj.get("type") == "attack-pattern":
            ext_refs = obj.get("external_references", [])
            tid = None
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id")
                    break
            if tid:
                index[tid] = {
                    "id": tid,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "tactics": [kp.get("phase_name") for kp in obj.get("kill_chain_phases", [])],
                    "platforms": obj.get("x_mitre_platforms", [])
                }
                
    with open(save_path, 'w', encoding='utf-8') as f:
        json.dump(index, f, indent=2)
    return index
