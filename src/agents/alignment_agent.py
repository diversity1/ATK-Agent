from core.schemas import ParsedRule, AlignmentResult
from tools.attack_retriever_tool import retrieve_top_candidates
import config

class AlignmentAgent:
    def __init__(self, attack_index: dict, llm_client=None):
        self.attack_index = attack_index
        self.llm_client = llm_client

    def process(self, parsed_rule: ParsedRule) -> AlignmentResult:
        candidates = self._retrieve_candidates(parsed_rule)
        
        if config.ENABLE_LLM and self.llm_client and self.llm_client.is_available():
            try:
                return self._rerank_candidates(parsed_rule, candidates)
            except Exception as e:
                import traceback
                print(f"LLM Reranking failed: {e}")
                traceback.print_exc()
                if config.FALLBACK_ON_ERROR:
                    return self._fallback_rank(parsed_rule, candidates)
                else:
                    raise e
        else:
            return self._fallback_rank(parsed_rule, candidates)

    def _retrieve_candidates(self, parsed_rule: ParsedRule):
        return retrieve_top_candidates(parsed_rule, self.attack_index, config.TOP_K_RETRIEVAL)

    def _rerank_candidates(self, parsed_rule: ParsedRule, candidates: list) -> AlignmentResult:
        from llm.rerank import rerank_with_llm
        return rerank_with_llm(parsed_rule, candidates, self.llm_client)

    def _fallback_rank(self, parsed_rule: ParsedRule, candidates: list) -> AlignmentResult:
        from llm.rerank import fallback_to_heuristic
        return fallback_to_heuristic(parsed_rule, candidates)
