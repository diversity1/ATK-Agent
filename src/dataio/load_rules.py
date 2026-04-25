import os
import glob

def load_rule_paths(dir_path: str, allowed_exts: list = None) -> list:
    if not allowed_exts:
        allowed_exts = [".yml", ".yaml", ".json"]
        
    paths = []
    for root, _, files in os.walk(dir_path):
        for f in files:
            if any(f.endswith(ext) for ext in allowed_exts):
                paths.append(os.path.join(root, f))
    return paths

def load_sigma_rules(dir_path: str) -> list:
    return load_rule_paths(dir_path, [".yml", ".yaml"])

def load_splunk_rules(dir_path: str) -> list:
    return load_rule_paths(dir_path, [".json", ".spl", ".txt"])
