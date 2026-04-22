from typing import List
from agents.manager_agent import ManagerAgent
from dataio.load_rules import load_rule_paths
from tools.rule_parser_tool import load_rule

def process_rule_batch(rule_paths: List[str], manager_agent: ManagerAgent, source_type="sigma"):
    raw_rules = []
    for path in rule_paths:
        rule_dict = load_rule(path)
        if rule_dict:
            raw_rules.append(rule_dict)
            
    batch_state = manager_agent.run_batch(raw_rules, source_type)
    return batch_state
