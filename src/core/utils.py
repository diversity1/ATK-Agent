import json
import yaml
import os

def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json(obj, path):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def load_yaml(path):
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def normalize_text(text):
    if not text:
        return ""
    return str(text).strip().lower()

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def safe_get(d, keys, default=None):
    if not isinstance(keys, (list, tuple)):
        keys = [keys]
    current = d
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current

def flatten_list(items):
    result = []
    for item in items:
        if isinstance(item, list):
            result.extend(flatten_list(item))
        else:
            result.append(item)
    return result
