from typing import Any, Dict, List, Optional, TypedDict
import uuid

import config
from core.state import RuleProcessState
from agents.manager_agent import ManagerAgent
from agents.query_planner_agent import QueryPlannerAgent
from agents.review_assistant_agent import ReviewAssistantAgent
from agents.semantic_extraction_agent import SemanticExtractionAgent
from agents.verification_agent import VerificationAgent

try:
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.graph import END, START, StateGraph
    HAS_LANGGRAPH = True
except ImportError:
    InMemorySaver = None
    StateGraph = None
    START = "__start__"
    END = "__end__"
    HAS_LANGGRAPH = False


class ATKAgentGraphState(TypedDict, total=False):
    raw_rule: Dict[str, Any]
    source_type: str
    file_path: str
    parsed_rule: Any
    semantic_profile: Any
    query_plan: Any
    alignment_result: Any
    verification_result: Any
    repair_result: Any
    review_brief: Any
    errors: List[str]
    graph_trace: List[str]
    review_status: str
    orchestration_mode: str


class LangGraphManagerAgent(ManagerAgent):
    """Graph-based orchestrator that keeps the existing agent implementations.

    The graph makes the orchestration explicit while preserving the previous
    ManagerAgent public API used by CLI batch processing and the Streamlit app.
    """

    orchestration_mode = "langgraph"

    def __init__(self):
        if not HAS_LANGGRAPH:
            raise RuntimeError("langgraph is not installed. Install it or use ManagerAgent.")
        super().__init__()
        self.semantic_extraction_agent = SemanticExtractionAgent(self.alignment_agent.llm_client)
        self.query_planner_agent = QueryPlannerAgent(self.alignment_agent.llm_client)
        self.verification_agent = VerificationAgent(self.alignment_agent.attack_index, self.alignment_agent.llm_client)
        self.review_assistant_agent = ReviewAssistantAgent(self.alignment_agent.llm_client)
        self.checkpointer = InMemorySaver()
        self.graph = self._build_graph()

    def run_one_rule(self, raw_rule: dict, source_type: str = "sigma", file_path: str = "") -> RuleProcessState:
        initial_state: ATKAgentGraphState = {
            "raw_rule": raw_rule,
            "source_type": source_type,
            "file_path": file_path,
            "errors": [],
            "graph_trace": [],
            "review_status": "not_required",
            "orchestration_mode": self.orchestration_mode,
        }

        try:
            graph_state = self.graph.invoke(
                initial_state,
                config={"configurable": {"thread_id": str(uuid.uuid4())}},
            )
            return self._to_rule_process_state(graph_state)
        except Exception as exc:
            state = RuleProcessState(orchestration_mode=self.orchestration_mode)
            state.add_error(str(exc))
            return state

    def _build_graph(self):
        workflow = StateGraph(ATKAgentGraphState)

        workflow.add_node("parse_rule", self._parse_node)
        workflow.add_node("semantic_extract", self._semantic_extract_node)
        workflow.add_node("plan_queries", self._plan_queries_node)
        workflow.add_node("align_attack", self._align_node)
        workflow.add_node("verify_alignment", self._verify_node)
        workflow.add_node("repair_tags", self._repair_node)
        workflow.add_node("review_brief", self._review_brief_node)
        workflow.add_node("human_review_gate", self._human_review_gate_node)
        workflow.add_node("finalize", self._finalize_node)

        workflow.add_edge(START, "parse_rule")
        workflow.add_conditional_edges(
            "parse_rule",
            self._route_after_parse,
            {"continue": "semantic_extract", "error": "finalize"},
        )
        workflow.add_conditional_edges(
            "semantic_extract",
            self._route_after_semantic_extract,
            {"continue": "plan_queries", "error": "finalize"},
        )
        workflow.add_conditional_edges(
            "plan_queries",
            self._route_after_query_plan,
            {"continue": "align_attack", "error": "finalize"},
        )
        workflow.add_conditional_edges(
            "align_attack",
            self._route_after_align,
            {"continue": "verify_alignment", "error": "finalize"},
        )
        workflow.add_conditional_edges(
            "verify_alignment",
            self._route_after_verify,
            {"continue": "repair_tags", "error": "finalize"},
        )
        workflow.add_conditional_edges(
            "repair_tags",
            self._route_after_repair,
            {"review": "review_brief", "finalize": "finalize"},
        )
        workflow.add_edge("review_brief", "human_review_gate")
        workflow.add_edge("human_review_gate", "finalize")
        workflow.add_edge("finalize", END)

        return workflow.compile(checkpointer=self.checkpointer)

    def _parse_node(self, state: ATKAgentGraphState) -> Dict[str, Any]:
        try:
            parsed = self.parsing_agent.process(
                state["raw_rule"],
                state.get("source_type", "sigma"),
                state.get("file_path", ""),
            )
            return {
                "parsed_rule": parsed,
                "graph_trace": self._append_trace(state, "parse_rule"),
            }
        except Exception as exc:
            return {
                "errors": self._append_error(state, exc),
                "graph_trace": self._append_trace(state, "parse_rule:error"),
            }

    def _semantic_extract_node(self, state: ATKAgentGraphState) -> Dict[str, Any]:
        try:
            parsed_rule = state.get("parsed_rule")
            if parsed_rule is None:
                raise ValueError("Cannot extract semantic profile before parsing the rule.")
            semantic_profile = self.semantic_extraction_agent.process(parsed_rule)
            return {
                "semantic_profile": semantic_profile,
                "graph_trace": self._append_trace(state, "semantic_extract"),
            }
        except Exception as exc:
            return {
                "errors": self._append_error(state, exc),
                "graph_trace": self._append_trace(state, "semantic_extract:error"),
            }

    def _plan_queries_node(self, state: ATKAgentGraphState) -> Dict[str, Any]:
        try:
            parsed_rule = state.get("parsed_rule")
            semantic_profile = state.get("semantic_profile")
            if parsed_rule is None or semantic_profile is None:
                raise ValueError("Cannot plan retrieval queries before parsing and semantic extraction.")
            query_plan = self.query_planner_agent.process(parsed_rule, semantic_profile)
            return {
                "query_plan": query_plan,
                "graph_trace": self._append_trace(state, "plan_queries"),
            }
        except Exception as exc:
            return {
                "errors": self._append_error(state, exc),
                "graph_trace": self._append_trace(state, "plan_queries:error"),
            }

    def _align_node(self, state: ATKAgentGraphState) -> Dict[str, Any]:
        try:
            parsed_rule = state.get("parsed_rule")
            if parsed_rule is None:
                raise ValueError("Cannot align ATT&CK techniques before parsing the rule.")
            alignment = self.alignment_agent.process(
                parsed_rule,
                state.get("semantic_profile"),
                state.get("query_plan"),
            )
            return {
                "alignment_result": alignment,
                "graph_trace": self._append_trace(state, "align_attack"),
            }
        except Exception as exc:
            return {
                "errors": self._append_error(state, exc),
                "graph_trace": self._append_trace(state, "align_attack:error"),
            }

    def _verify_node(self, state: ATKAgentGraphState) -> Dict[str, Any]:
        try:
            parsed_rule = state.get("parsed_rule")
            semantic_profile = state.get("semantic_profile")
            alignment_result = state.get("alignment_result")
            if parsed_rule is None or semantic_profile is None or alignment_result is None:
                raise ValueError("Cannot verify alignment before parsing, semantic extraction, and alignment complete.")
            verification = self.verification_agent.process(parsed_rule, semantic_profile, alignment_result)
            adjusted_alignment = self._apply_verification_adjustment(alignment_result, verification)
            return {
                "verification_result": verification,
                "alignment_result": adjusted_alignment,
                "graph_trace": self._append_trace(state, "verify_alignment"),
            }
        except Exception as exc:
            return {
                "errors": self._append_error(state, exc),
                "graph_trace": self._append_trace(state, "verify_alignment:error"),
            }

    def _repair_node(self, state: ATKAgentGraphState) -> Dict[str, Any]:
        try:
            parsed_rule = state.get("parsed_rule")
            alignment_result = state.get("alignment_result")
            if parsed_rule is None or alignment_result is None:
                raise ValueError("Cannot repair tags before parsing and alignment complete.")
            repair = self.repair_agent.process(parsed_rule, alignment_result)
            verification_result = state.get("verification_result")
            if verification_result and getattr(verification_result, "review_required", False) and not repair.needs_review:
                repair = repair.model_copy(update={
                    "needs_review": True,
                    "repair_reason": repair.repair_reason + " Verification agent requested analyst review.",
                })
            return {
                "repair_result": repair,
                "graph_trace": self._append_trace(state, "repair_tags"),
            }
        except Exception as exc:
            return {
                "errors": self._append_error(state, exc),
                "graph_trace": self._append_trace(state, "repair_tags:error"),
            }

    def _review_brief_node(self, state: ATKAgentGraphState) -> Dict[str, Any]:
        try:
            parsed_rule = state.get("parsed_rule")
            semantic_profile = state.get("semantic_profile")
            alignment_result = state.get("alignment_result")
            verification_result = state.get("verification_result")
            repair_result = state.get("repair_result")
            if not all([parsed_rule, semantic_profile, alignment_result, verification_result, repair_result]):
                raise ValueError("Cannot build review brief before all upstream results are available.")
            review_brief = self.review_assistant_agent.process(
                parsed_rule,
                semantic_profile,
                alignment_result,
                verification_result,
                repair_result,
            )
            return {
                "review_brief": review_brief,
                "graph_trace": self._append_trace(state, "review_brief"),
            }
        except Exception as exc:
            return {
                "errors": self._append_error(state, exc),
                "graph_trace": self._append_trace(state, "review_brief:error"),
            }


    def _human_review_gate_node(self, state: ATKAgentGraphState) -> Dict[str, Any]:
        return {
            "review_status": "pending",
            "graph_trace": self._append_trace(state, "human_review_gate"),
        }

    def _finalize_node(self, state: ATKAgentGraphState) -> Dict[str, Any]:
        return {
            "orchestration_mode": self.orchestration_mode,
            "graph_trace": self._append_trace(state, "finalize"),
        }

    def _route_after_parse(self, state: ATKAgentGraphState) -> str:
        if state.get("errors") or state.get("parsed_rule") is None:
            return "error"
        return "continue"

    def _route_after_semantic_extract(self, state: ATKAgentGraphState) -> str:
        if state.get("errors") or state.get("semantic_profile") is None:
            return "error"
        return "continue"

    def _route_after_query_plan(self, state: ATKAgentGraphState) -> str:
        if state.get("errors") or state.get("query_plan") is None:
            return "error"
        return "continue"

    def _route_after_align(self, state: ATKAgentGraphState) -> str:
        if state.get("errors") or state.get("alignment_result") is None:
            return "error"
        return "continue"

    def _route_after_verify(self, state: ATKAgentGraphState) -> str:
        if state.get("errors") or state.get("verification_result") is None:
            return "error"
        return "continue"

    def _route_after_repair(self, state: ATKAgentGraphState) -> str:
        if state.get("errors"):
            return "finalize"
        repair_result = state.get("repair_result")
        if repair_result and getattr(repair_result, "needs_review", False):
            return "review"
        return "finalize"

    def _to_rule_process_state(self, graph_state: ATKAgentGraphState) -> RuleProcessState:
        return RuleProcessState(
            parsed_rule=graph_state.get("parsed_rule"),
            semantic_profile=graph_state.get("semantic_profile"),
            query_plan=graph_state.get("query_plan"),
            alignment_result=graph_state.get("alignment_result"),
            verification_result=graph_state.get("verification_result"),
            repair_result=graph_state.get("repair_result"),
            review_brief=graph_state.get("review_brief"),
            errors=graph_state.get("errors", []),
            graph_trace=graph_state.get("graph_trace", []),
            review_status=graph_state.get("review_status", "not_required"),
            orchestration_mode=graph_state.get("orchestration_mode", self.orchestration_mode),
        )

    @staticmethod
    def _apply_verification_adjustment(alignment_result, verification_result):
        confidence = max(
            0.0,
            min(0.99, float(alignment_result.confidence) + float(verification_result.confidence_adjustment)),
        )
        reason = alignment_result.reason
        if verification_result.reason:
            reason = f"{reason} Verification: {verification_result.reason}"
        return alignment_result.model_copy(update={
            "confidence": confidence,
            "abstain": confidence < config.ABSTAIN_THRESHOLD,
            "reason": reason,
        })

    @staticmethod
    def _append_trace(state: ATKAgentGraphState, node_name: str) -> List[str]:
        return [*state.get("graph_trace", []), node_name]

    @staticmethod
    def _append_error(state: ATKAgentGraphState, error: Exception) -> List[str]:
        return [*state.get("errors", []), str(error)]


def create_manager_agent() -> ManagerAgent:
    if HAS_LANGGRAPH:
        return LangGraphManagerAgent()
    return ManagerAgent()
