from core.schemas import ParsedRule
from tools.rule_parser_tool import load_rule, parse_sigma_rule, parse_splunk_rule

class ParsingAgent:
    def process(self, raw_rule: dict, source_type: str = "sigma", file_path: str = "") -> ParsedRule:
        if source_type == "sigma":
            parsed = parse_sigma_rule(raw_rule, file_path)
        else:
            parsed = parse_splunk_rule(raw_rule, file_path)
        return parsed

    def _summarize_rule(self, parsed_rule: ParsedRule) -> str:
        return parsed_rule.normalized_rule_text
