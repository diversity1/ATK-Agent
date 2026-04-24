from typing import List

from core.schemas import ParsedRule, QueryPlan, SemanticProfile
from llm.json_utils import parse_json_object


class QueryPlannerAgent:
    def __init__(self, llm_client=None):
        self.llm_client = llm_client

    def process(self, parsed_rule: ParsedRule, semantic_profile: SemanticProfile) -> QueryPlan:
        if self.llm_client and self.llm_client.is_available():
            try:
                return self._plan_with_llm(parsed_rule, semantic_profile)
            except Exception:
                return self._plan_with_heuristic(parsed_rule, semantic_profile)
        return self._plan_with_heuristic(parsed_rule, semantic_profile)

    def _plan_with_llm(self, parsed_rule: ParsedRule, semantic_profile: SemanticProfile) -> QueryPlan:
        prompt = f"""You are an ATT&CK retrieval query planning API.
Generate complementary retrieval queries for mapping a detection rule to MITRE ATT&CK.

Rule normalized text:
{parsed_rule.normalized_rule_text}

Semantic profile:
{semantic_profile.model_dump()}

Output strict JSON only:
{{
  "keyword_query": "exact indicators, event ids, tools, commands",
  "behavior_query": "natural language adversary behavior",
  "datasource_query": "log source and ATT&CK data source terminology",
  "tactic_query": "likely tactic and technique family query",
  "queries": ["3 to 5 final retrieval queries"]
}}
"""
        raw = self.llm_client.chat([
            {"role": "system", "content": "Return ATT&CK retrieval query-plan JSON only."},
            {"role": "user", "content": prompt},
        ])
        data = parse_json_object(raw)
        queries = self._list_of_strings(data.get("queries", []))
        plan = QueryPlan(
            keyword_query=str(data.get("keyword_query", "")),
            behavior_query=str(data.get("behavior_query", "")),
            datasource_query=str(data.get("datasource_query", "")),
            tactic_query=str(data.get("tactic_query", "")),
            queries=queries,
            planning_mode="llm",
        )
        if not plan.queries:
            plan.queries = self._collect_queries(plan, parsed_rule)
        return plan

    def _plan_with_heuristic(self, parsed_rule: ParsedRule, semantic_profile: SemanticProfile) -> QueryPlan:
        tools = " ".join(semantic_profile.tools_or_binaries)
        observables = " ".join(str(item.get("value", "")) for item in semantic_profile.observables)
        tactics = " ".join(semantic_profile.likely_tactics)
        data_sources = " ".join(semantic_profile.required_data_sources)

        plan = QueryPlan(
            keyword_query=" ".join(part for part in [tools, observables] if part).strip(),
            behavior_query=" ".join(part for part in [semantic_profile.main_behavior, parsed_rule.title] if part).strip(),
            datasource_query=" ".join(part for part in [
                parsed_rule.product,
                parsed_rule.category,
                parsed_rule.service,
                data_sources,
            ] if part).strip(),
            tactic_query=tactics,
            planning_mode="heuristic",
        )
        plan.queries = self._collect_queries(plan, parsed_rule)
        return plan

    @staticmethod
    def _collect_queries(plan: QueryPlan, parsed_rule: ParsedRule) -> List[str]:
        queries = [
            plan.keyword_query,
            plan.behavior_query,
            plan.datasource_query,
            plan.tactic_query,
            parsed_rule.normalized_rule_text,
        ]
        seen = set()
        ordered = []
        for query in queries:
            query = (query or "").strip()
            key = query.lower()
            if query and key not in seen:
                seen.add(key)
                ordered.append(query)
        return ordered[:5]

    @staticmethod
    def _list_of_strings(value) -> List[str]:
        if not isinstance(value, list):
            return []
        return [str(item).strip() for item in value if str(item).strip()]
