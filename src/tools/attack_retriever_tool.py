import json
import os
import numpy as np
from typing import List, Dict, Any
from core.schemas import ParsedRule, CandidateTechnique
import config

try:
    from sentence_transformers import SentenceTransformer
    from rank_bm25 import BM25Okapi
    from sklearn.metrics.pairwise import cosine_similarity
    HAS_RAG_DEPS = True
except ImportError:
    HAS_RAG_DEPS = False

class AttackRetrieverEngine:
    def __init__(self, attack_index: dict):
        self.attack_index = attack_index
        self.keys = list(attack_index.keys())
        self.corpus_texts = []
        
        for tid in self.keys:
            doc = self.attack_index[tid]
            # Construct rich text for indexing
            text = f"{tid} {doc.get('name', '')} {doc.get('description', '')}"
            self.corpus_texts.append(text)
            
        self.bm25 = None
        self.dense_model = None
        self.dense_embeddings = None
        
        if HAS_RAG_DEPS:
            print("Initializing RAG Models (BM25 & Sentence-Transformers)...")
            # Build BM25
            tokenized_corpus = [doc.lower().split() for doc in self.corpus_texts]
            self.bm25 = BM25Okapi(tokenized_corpus)
            
            # Build Dense
            # Use a very fast small model for prototyping
            self.dense_model = SentenceTransformer("all-MiniLM-L6-v2")
            self.dense_embeddings = self.dense_model.encode(self.corpus_texts, convert_to_numpy=True)
            print("RAG Models Initialized.")

    def retrieve(self, parsed_rule: ParsedRule, top_k: int = 10) -> List[CandidateTechnique]:
        if not HAS_RAG_DEPS:
            return self._fallback_retrieve(parsed_rule, top_k)
            
        query = parsed_rule.normalized_rule_text
        
        # 1. BM25 Sparse Search
        tokenized_query = query.lower().split()
        bm25_scores = self.bm25.get_scores(tokenized_query)
        bm25_ranks = np.argsort(bm25_scores)[::-1]
        
        # 2. Dense Semantic Search
        query_emb = self.dense_model.encode([query], convert_to_numpy=True)
        dense_scores = cosine_similarity(query_emb, self.dense_embeddings)[0]
        dense_ranks = np.argsort(dense_scores)[::-1]
        
        # 3. RRF (Reciprocal Rank Fusion)
        k_rrf = 60
        rrf_scores = np.zeros(len(self.keys))
        
        for rank, doc_idx in enumerate(bm25_ranks):
            rrf_scores[doc_idx] += 1.0 / (k_rrf + rank + 1)
            
        for rank, doc_idx in enumerate(dense_ranks):
            rrf_scores[doc_idx] += 1.0 / (k_rrf + rank + 1)
            
        # Add a slight boost for existing tags (tag hint)
        for idx, tid in enumerate(self.keys):
            if tid in parsed_rule.existing_attack_tags:
                rrf_scores[idx] += 0.05 # small boost
                
        final_ranks = np.argsort(rrf_scores)[::-1][:top_k]
        
        candidates = []
        for idx in final_ranks:
            tid = self.keys[idx]
            doc = self.attack_index[tid]
            score = rrf_scores[idx]
            candidates.append(CandidateTechnique(
                technique_id=tid,
                technique_name=doc.get("name", ""),
                retrieval_score=float(score),
                tactics=doc.get("tactics", []),
                platforms=doc.get("platforms", []),
                why={"rrf_score": score, "bm25_score": bm25_scores[idx], "dense_score": dense_scores[idx]}
            ))
            
        return candidates

    def _fallback_retrieve(self, parsed_rule: ParsedRule, top_k: int = 10) -> List[CandidateTechnique]:
        # Original naive heuristic logic
        rule_text = parsed_rule.normalized_rule_text.lower()
        rule_tokens = set(rule_text.split())
        candidates = []
        
        for tid, doc in self.attack_index.items():
            name = doc.get("name", "").lower()
            desc = doc.get("description", "").lower()
            doc_tokens = set(name.split() + desc.split())
            
            t_score = 0.0
            if rule_tokens and doc_tokens:
                intersection = rule_tokens.intersection(doc_tokens)
                t_score = len(intersection) / float(len(rule_tokens))
                
            p_score = 0.5 if parsed_rule.product.lower() in [p.lower() for p in doc.get("platforms", [])] else 0.0
            h_score = 1.0 if tid in parsed_rule.existing_attack_tags else 0.0
            
            total_score = t_score + p_score + h_score
            if total_score > 0:
                candidates.append(CandidateTechnique(
                    technique_id=tid, technique_name=doc.get("name", ""), retrieval_score=total_score,
                    tactics=doc.get("tactics", []), platforms=doc.get("platforms", []),
                    why={"text_score": t_score, "platform_score": p_score, "hint_score": h_score}
                ))
        candidates.sort(key=lambda x: x.retrieval_score, reverse=True)
        return candidates[:top_k]

# Global instance will be set by AlignmentAgent
_retriever_engine = None

def retrieve_top_candidates(parsed_rule: ParsedRule, attack_index: dict, top_k: int = 10) -> List[CandidateTechnique]:
    global _retriever_engine
    if _retriever_engine is None:
        _retriever_engine = AttackRetrieverEngine(attack_index)
    return _retriever_engine.retrieve(parsed_rule, top_k)
