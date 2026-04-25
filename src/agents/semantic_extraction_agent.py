import re
from typing import List

from core.schemas import ParsedRule, SemanticProfile
from llm.json_utils import parse_json_object


class SemanticExtractionAgent:
    def __init__(self, llm_client=None):
        self.llm_client = llm_client

    def process(self, parsed_rule: ParsedRule) -> SemanticProfile:
        if self.llm_client and self.llm_client.is_available():
            try:
                return self._extract_with_llm(parsed_rule)
            except Exception:
                return self._extract_with_heuristic(parsed_rule)
        return self._extract_with_heuristic(parsed_rule)

    def _extract_with_llm(self, parsed_rule: ParsedRule) -> SemanticProfile:
        prompt = f"""You are a cybersecurity detection-rule semantic extraction API.
Extract the adversary behavior semantics from this detection rule.

Rule source type: {parsed_rule.source_type}
Rule query language: {parsed_rule.query_language}
Rule title: {parsed_rule.title}
Rule description: {parsed_rule.description}
Log source: product={parsed_rule.product}, category={parsed_rule.category}, service={parsed_rule.service}
Normalized telemetry: {parsed_rule.telemetry}
Data components: {parsed_rule.data_components}
Structured observables: {parsed_rule.observables[:20]}
Detection indicators: {parsed_rule.detection_text}
Existing ATT&CK tags: {parsed_rule.existing_attack_tags}

Output strict JSON only:
{{
  "main_behavior": "short behavior summary",
  "observables": [{{"type": "event_id|process|command|script_keyword|registry|network|other", "value": "..."}}],
  "tools_or_binaries": ["powershell", "rundll32", "..."],
  "likely_tactics": ["execution", "defense-evasion"],
  "required_data_sources": ["Script Execution", "Process Creation"],
  "negative_constraints": ["what this rule likely does not detect"],
  "confidence": 0.0
}}
"""
        raw = self.llm_client.chat([
            {"role": "system", "content": "Return cybersecurity extraction JSON only."},
            {"role": "user", "content": prompt},
        ])
        data = parse_json_object(raw)
        profile = SemanticProfile(
            main_behavior=str(data.get("main_behavior", "")),
            observables=self._list_of_dicts(data.get("observables", [])),
            tools_or_binaries=self._list_of_strings(data.get("tools_or_binaries", [])),
            likely_tactics=self._list_of_strings(data.get("likely_tactics", [])),
            required_data_sources=self._list_of_strings(data.get("required_data_sources", [])),
            negative_constraints=self._list_of_strings(data.get("negative_constraints", [])),
            confidence=float(data.get("confidence", 0.7) or 0.7),
            extraction_mode="llm",
        )
        if not profile.main_behavior:
            return self._extract_with_heuristic(parsed_rule)
        return profile

    def _extract_with_heuristic(self, parsed_rule: ParsedRule) -> SemanticProfile:
        text = " ".join([
            parsed_rule.title or "",
            parsed_rule.description or "",
            parsed_rule.detection_text or "",
            parsed_rule.normalized_rule_text or "",
        ]).lower()

        observables = []
        for event_id in re.findall(r"\b\d{3,5}\b", parsed_rule.detection_text or ""):
            observables.append({"type": "event_id", "value": event_id})

        known_tools = [
            "powershell", "cmd", "wscript", "cscript", "wmic", "rundll32",
            "regsvr32", "schtasks", "mimikatz", "certutil", "msbuild",
            "bitsadmin", "curl", "wget", "python", "bash",
        ]
        tools = [tool for tool in known_tools if tool in text]

        script_keywords = [
            "invoke-expression", "iex", "encodedcommand", "downloadstring",
            "frombase64string", "scriptblocktext",
        ]
        for keyword in script_keywords:
            if keyword in text:
                observables.append({"type": "script_keyword", "value": keyword})

        tactics = self._infer_tactics(text)
        data_sources = self._infer_data_sources(parsed_rule)
        behavior_parts = []
        if tools:
            behavior_parts.append(", ".join(tools[:3]))
        if parsed_rule.detection_text:
            behavior_parts.append(parsed_rule.detection_text.replace("Detection indicators:", "").strip()[:120])

        return SemanticProfile(
            main_behavior="; ".join(part for part in behavior_parts if part) or parsed_rule.title,
            observables=observables,
            tools_or_binaries=tools,
            likely_tactics=tactics,
            required_data_sources=data_sources,
            negative_constraints=[],
            confidence=0.45,
            extraction_mode="heuristic",
        )

    @staticmethod
    def _infer_tactics(text: str) -> List[str]:
        tactic_rules = [
            ("credential-access", ["lsass", "mimikatz", "credential", "dump"]),
            ("execution", ["powershell", "cmd", "script", "process creation", "execute"]),
            ("defense-evasion", ["encoded", "obfuscat", "bypass", "rundll32", "regsvr32"]),
            ("persistence", ["schtasks", "run key", "startup", "service creation"]),
            ("discovery", ["whoami", "net user", "systeminfo", "query"]),
            ("command-and-control", ["network connection", "dns", "http", "callback"]),
        ]
        tactics = []
        for tactic, keywords in tactic_rules:
            if any(keyword in text for keyword in keywords):
                tactics.append(tactic)
        return tactics[:3]

    @staticmethod
    def _infer_data_sources(parsed_rule: ParsedRule) -> List[str]:
        data_sources = []
        data_sources.extend(getattr(parsed_rule, "telemetry", []) or [])
        data_sources.extend(getattr(parsed_rule, "data_components", []) or [])
        category = (parsed_rule.category or "").lower()
        service = (parsed_rule.service or "").lower()
        if "process_creation" in category:
            data_sources.append("Process Creation")
        if "process_access" in category:
            data_sources.append("Process Access")
        if "network_connection" in category:
            data_sources.append("Network Traffic")
        if "dns" in category:
            data_sources.append("DNS")
        if "powershell" in service:
            data_sources.append("Script Execution")
        seen = set()
        deduped = []
        for data_source in data_sources:
            key = data_source.lower()
            if key not in seen:
                seen.add(key)
                deduped.append(data_source)
        return deduped

    @staticmethod
    def _list_of_strings(value) -> List[str]:
        if not isinstance(value, list):
            return []
        return [str(item).strip() for item in value if str(item).strip()]

    @staticmethod
    def _list_of_dicts(value) -> List[dict]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]
