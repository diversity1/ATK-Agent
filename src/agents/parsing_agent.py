from core.schemas import ParsedRule
from parsers.base import ir_to_parsed_rule
from parsers.registry import get_rule_adapter

class ParsingAgent:
    def process(self, raw_rule: dict, source_type: str = "sigma", file_path: str = "") -> ParsedRule:
        adapter = get_rule_adapter(source_type)
        rule_ir = adapter.parse(raw_rule, file_path)
        return ir_to_parsed_rule(rule_ir)

    def _summarize_rule(self, parsed_rule: ParsedRule) -> str:
        return parsed_rule.normalized_rule_text
