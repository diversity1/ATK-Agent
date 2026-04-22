import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import config
from core.registry import registry
from core.utils import ensure_dir
from dataio.load_rules import load_sigma_rules
from dataio.load_attack import load_attack_index
from llm.client import LLMClient
from pipelines.process_rule_batch import process_rule_batch
from dataio.save_results import save_rule_results_jsonl, save_rule_results_csv, save_run_report, save_coverage_csv
from agents.manager_agent import ManagerAgent

def setup():
    ensure_dir(config.OUTPUTS_DIR)
    
    # Load index
    if not os.path.exists(config.ATTACK_INDEX_PATH):
        # Create a dummy index if not exists to avoid crashing
        dummy_index = {
            "T1059": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["execution"], "platforms": ["Windows"]},
            "T1059.001": {"id": "T1059.001", "name": "PowerShell", "tactics": ["execution"], "platforms": ["Windows"]},
            "T1027": {"id": "T1027", "name": "Obfuscated Files or Information", "tactics": ["defense-evasion"], "platforms": ["Windows", "Linux"]}
        }
        ensure_dir(config.ATTACK_DATA_DIR)
        with open(config.ATTACK_INDEX_PATH, 'w') as f:
            import json
            json.dump(dummy_index, f)
            
    attack_index = load_attack_index(config.ATTACK_INDEX_PATH)
    registry.register("attack_index", attack_index)
    
    # Init LLM
    llm_client = LLMClient()
    registry.register("llm_client", llm_client)
    
    registry.register("manager_agent", ManagerAgent())

def main():
    setup()
    
    sigma_dir = config.SIGMA_RULES_DIR
    if not os.path.exists(sigma_dir):
        ensure_dir(sigma_dir)
        print(f"Please place some sigma rules in {sigma_dir}")
        
    rule_paths = load_sigma_rules(sigma_dir)
    if not rule_paths:
        print(f"No rules found in {sigma_dir}.")
        return

    print(f"Found {len(rule_paths)} rules. Processing...")
    
    manager = registry.get("manager_agent")
    batch_state = process_rule_batch(rule_paths, manager, "sigma")
    
    # Save outputs
    results = [manager._build_final_rule_record(r) for r in batch_state.rules]
    save_rule_results_jsonl(results, os.path.join(config.OUTPUTS_DIR, "rule_results.jsonl"))
    save_rule_results_csv(results, os.path.join(config.OUTPUTS_DIR, "rule_results.csv"))
    
    if batch_state.coverage_summary:
        save_coverage_csv(batch_state.coverage_summary["technique_coverage"], os.path.join(config.OUTPUTS_DIR, "coverage_summary.csv"))
        save_coverage_csv(batch_state.coverage_summary["tactic_coverage"], os.path.join(config.OUTPUTS_DIR, "coverage_by_tactic.csv"))
        
    save_run_report({"run_id": batch_state.run_id, "processed_rules": len(results)}, os.path.join(config.OUTPUTS_DIR, "run_report.json"))
    
    print("Done! Check data/outputs/ for results.")

if __name__ == "__main__":
    main()
