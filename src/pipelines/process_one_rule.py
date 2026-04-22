from agents.manager_agent import ManagerAgent

def process_one_rule(raw_rule: dict, manager_agent: ManagerAgent, source_type="sigma"):
    state = manager_agent.run_one_rule(raw_rule, source_type)
    return state
