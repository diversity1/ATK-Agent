import re
from typing import List
from core.schemas import ParsedRule, CandidateTechnique
import config

try:
    from rank_bm25 import BM25Okapi
    HAS_BM25 = True
except ImportError:
    HAS_BM25 = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    np = None
    HAS_NUMPY = False

try:
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity
    HAS_DENSE_DEPS = True
except ImportError:
    HAS_DENSE_DEPS = False

LOGSOURCE_HINTS = {
    "category:process_creation": [
        ("process creation", 0.45),
        ("command execution", 0.25),
        ("process", 0.10),
    ],
    "category:process_access": [
        ("process access", 0.45),
        ("os api execution", 0.25),
        ("process", 0.10),
    ],
    "category:create_remote_thread": [
        ("process injection", 0.40),
        ("process access", 0.30),
        ("os api execution", 0.20),
    ],
    "category:network_connection": [
        ("network connection", 0.45),
        ("network traffic", 0.30),
        ("connection", 0.15),
    ],
    "category:dns_query": [
        ("dns", 0.55),
        ("network traffic", 0.25),
        ("domain name", 0.15),
    ],
    "category:image_load": [
        ("module load", 0.45),
        ("image load", 0.30),
        ("dll", 0.15),
    ],
    "category:driver_load": [
        ("driver load", 0.45),
        ("driver", 0.25),
        ("module load", 0.15),
    ],
    "category:pipe_created": [
        ("named pipe", 0.50),
        ("pipe", 0.20),
    ],
    "category:wmi_event": [
        ("wmi", 0.50),
        ("windows management instrumentation", 0.35),
    ],
    "category:registry_add": [
        ("windows registry key modification", 0.45),
        ("registry key modification", 0.35),
        ("registry", 0.15),
    ],
    "service:powershell": [
        ("script execution", 0.45),
        ("powershell", 0.30),
        ("command execution", 0.15),
        ("4104", 0.20),
    ],
    "service:security": [
        ("wineventlog:security", 0.35),
        ("logon session", 0.25),
        ("user account authentication", 0.25),
    ],
    "service:sysmon": [
        ("sysmon", 0.20),
    ],
    "product:windows": [
        ("windows", 0.20),
        ("wineventlog", 0.15),
    ],
    "product:linux": [
        ("linux", 0.20),
        ("auditd", 0.15),
        ("syslog", 0.15),
    ],
}

class AttackRetrieverEngine:
    def __init__(self, attack_index: dict):
        self.attack_index = attack_index
        self.keys = list(attack_index.keys())
        self.corpus_texts = []
        
        for tid in self.keys:
            doc = self.attack_index[tid]
            # Build rich semantic text for indexing:
            # technique name repeated for emphasis + full description + tactic context
            name        = doc.get("name", "")
            desc        = doc.get("description", "")
            detection   = doc.get("detection", "")
            tactics     = " ".join(doc.get("tactics", []))
            platforms   = " ".join(doc.get("platforms", []))
            data_srcs   = " ".join(doc.get("data_sources", []))

            # Truncate description to avoid embedding dimension issues
            desc_trunc = desc[:600] if desc else ""
            detection_trunc = detection[:400] if detection else ""

            text = (
                f"{tid} {name}. "
                f"Tactics: {tactics}. "
                f"Platforms: {platforms}. "
                f"Data Sources: {data_srcs}. "
                f"Detection: {detection_trunc}. "
                f"Description: {desc_trunc}"
            )
            self.corpus_texts.append(text)
            
        self.bm25 = None
        self.dense_model = None
        self.dense_embeddings = None
        
        if HAS_BM25 and HAS_NUMPY:
            try:
                tokenized_corpus = [self._tokenize(doc) for doc in self.corpus_texts]
                self.bm25 = BM25Okapi(tokenized_corpus)
                print("BM25 retriever initialized.")
            except Exception as exc:
                self.bm25 = None
                print(f"BM25 retriever unavailable, using heuristic fallback: {exc}")
        elif HAS_BM25 and not HAS_NUMPY:
            print("BM25 retriever disabled: numpy is required for ranking.")

        if config.ENABLE_DENSE_RETRIEVAL:
            self._try_init_dense_model()

    @staticmethod
    def _tokenize(text: str) -> list:
        return text.lower().split()

    def _try_init_dense_model(self) -> None:
        if not HAS_DENSE_DEPS:
            print("Dense retriever disabled: optional dense dependencies are not installed.")
            return

        try:
            print(f"Initializing dense retriever: {config.EMBEDDING_MODEL}")
            self.dense_model = SentenceTransformer(
                config.EMBEDDING_MODEL,
                cache_folder=config.EMBEDDING_CACHE_DIR or None,
                local_files_only=config.EMBEDDING_LOCAL_FILES_ONLY,
            )
            self.dense_embeddings = self.dense_model.encode(self.corpus_texts, convert_to_numpy=True)
            print("Dense retriever initialized.")
        except TypeError:
            # Older sentence-transformers versions may not support local_files_only.
            try:
                if config.EMBEDDING_LOCAL_FILES_ONLY:
                    print("Dense retriever disabled: installed sentence-transformers does not support local_files_only.")
                    return
                self.dense_model = SentenceTransformer(
                    config.EMBEDDING_MODEL,
                    cache_folder=config.EMBEDDING_CACHE_DIR or None,
                )
                self.dense_embeddings = self.dense_model.encode(self.corpus_texts, convert_to_numpy=True)
                print("Dense retriever initialized.")
            except Exception as exc:
                self.dense_model = None
                self.dense_embeddings = None
                print(f"Dense retriever unavailable, continuing without it: {exc}")
        except Exception as exc:
            self.dense_model = None
            self.dense_embeddings = None
            print(f"Dense retriever unavailable, continuing without it: {exc}")

    @staticmethod
    def _normalize_logsource_value(value: str) -> str:
        return (value or "").strip().lower().replace("-", "_")

    def _build_logsource_hints(self, parsed_rule: ParsedRule) -> list:
        hints = []
        for field in ("product", "category", "service"):
            value = self._normalize_logsource_value(getattr(parsed_rule, field, ""))
            if not value:
                continue
            hints.append((value.replace("_", " "), 0.10))
            hints.extend(LOGSOURCE_HINTS.get(f"{field}:{value}", []))

        for event_id in re.findall(r"\b\d{3,5}\b", parsed_rule.detection_text or ""):
            hints.append((event_id, 0.12))

        deduped = {}
        for term, weight in hints:
            term = term.strip().lower()
            if term:
                deduped[term] = max(deduped.get(term, 0.0), weight)
        return list(deduped.items())

    @staticmethod
    def _doc_data_source_text(doc: dict) -> str:
        parts = []
        parts.extend(doc.get("data_sources", []) or [])
        for item in doc.get("log_sources", []) or []:
            if isinstance(item, dict):
                parts.extend(str(item.get(field, "")) for field in ("component", "name", "channel"))
            else:
                parts.append(str(item))
        parts.extend(doc.get("platforms", []) or [])
        parts.append(doc.get("detection", "") or "")
        return " ".join(str(part) for part in parts if part).lower()

    def _compute_logsource_score(self, parsed_rule: ParsedRule, doc: dict) -> float:
        data_source_text = self._doc_data_source_text(doc)
        if not data_source_text:
            return 0.0

        score = 0.0
        for term, weight in self._build_logsource_hints(parsed_rule):
            if term in data_source_text:
                score += weight

        product = self._normalize_logsource_value(parsed_rule.product)
        platforms = {str(p).lower() for p in doc.get("platforms", []) or []}
        if product == "windows" and "windows" in platforms:
            score += 0.20
        elif product == "linux" and "linux" in platforms:
            score += 0.20
        elif product and product in platforms:
            score += 0.20

        return min(1.0, score)

    def retrieve(self, parsed_rule: ParsedRule, top_k: int = 10, query_texts: list = None) -> List[CandidateTechnique]:
        if not self.bm25 and not self.dense_model:
            return self._fallback_retrieve(parsed_rule, top_k, query_texts=query_texts)
            
        query_texts = self._normalize_queries(parsed_rule, query_texts)
        ranks_by_source = []
        bm25_score_sets = []
        dense_score_sets = []
        
        for query in query_texts:
            if self.bm25:
                tokenized_query = self._tokenize(query)
                bm25_scores = self.bm25.get_scores(tokenized_query)
                bm25_ranks = np.argsort(bm25_scores)[::-1]
                ranks_by_source.append(bm25_ranks)
                bm25_score_sets.append(bm25_scores)
            
            if self.dense_model and self.dense_embeddings is not None:
                query_emb = self.dense_model.encode([query], convert_to_numpy=True)
                dense_scores = cosine_similarity(query_emb, self.dense_embeddings)[0]
                dense_ranks = np.argsort(dense_scores)[::-1]
                ranks_by_source.append(dense_ranks)
                dense_score_sets.append(dense_scores)
        
        # 3. RRF (Reciprocal Rank Fusion)
        k_rrf = 60
        rrf_scores = np.zeros(len(self.keys))
        
        for source_ranks in ranks_by_source:
            for rank, doc_idx in enumerate(source_ranks):
                rrf_scores[doc_idx] += 1.0 / (k_rrf + rank + 1)
            
        for idx, tid in enumerate(self.keys):
            logsource_score = self._compute_logsource_score(parsed_rule, self.attack_index[tid])
            rrf_scores[idx] += logsource_score * config.LOGSOURCE_MATCH_WEIGHT
                
        final_ranks = np.argsort(rrf_scores)[::-1][:top_k]
        
        candidates = []
        for idx in final_ranks:
            tid = self.keys[idx]
            doc = self.attack_index[tid]
            score = rrf_scores[idx]
            why = {
                "rrf_score": float(score),
                "query_count": len(query_texts),
                "retrieval_queries": query_texts[:5],
            }
            if bm25_score_sets:
                why["bm25_score"] = float(max(scores[idx] for scores in bm25_score_sets))
            if dense_score_sets:
                why["dense_score"] = float(max(scores[idx] for scores in dense_score_sets))
            why["logsource_score"] = self._compute_logsource_score(parsed_rule, doc)
            candidates.append(CandidateTechnique(
                technique_id=tid,
                technique_name=doc.get("name", ""),
                retrieval_score=float(score),
                tactics=doc.get("tactics", []),
                platforms=doc.get("platforms", []),
                why=why
            ))
            
        return candidates

    def _fallback_retrieve(self, parsed_rule: ParsedRule, top_k: int = 10, query_texts: list = None) -> List[CandidateTechnique]:
        # Original naive heuristic logic
        queries = self._normalize_queries(parsed_rule, query_texts)
        rule_text = " ".join(queries).lower()
        rule_tokens = set(rule_text.split())
        candidates = []
        
        for tid, doc in self.attack_index.items():
            name = doc.get("name", "").lower()
            desc = doc.get("description", "").lower()
            detection = doc.get("detection", "").lower()
            data_sources = " ".join(doc.get("data_sources", []) or []).lower()
            doc_tokens = set(name.split() + desc.split() + detection.split() + data_sources.split())
            
            t_score = 0.0
            if rule_tokens and doc_tokens:
                intersection = rule_tokens.intersection(doc_tokens)
                t_score = len(intersection) / float(len(rule_tokens))
                
            p_score = 0.5 if parsed_rule.product.lower() in [p.lower() for p in doc.get("platforms", [])] else 0.0
            h_score = 0.05 if tid in parsed_rule.existing_attack_tags else 0.0
            logsource_score = self._compute_logsource_score(parsed_rule, doc)
            
            total_score = t_score + p_score + h_score + (0.5 * logsource_score)
            if total_score > 0:
                candidates.append(CandidateTechnique(
                    technique_id=tid, technique_name=doc.get("name", ""), retrieval_score=total_score,
                    tactics=doc.get("tactics", []), platforms=doc.get("platforms", []),
                    why={
                        "text_score": t_score,
                        "platform_score": p_score,
                        "hint_score": h_score,
                        "logsource_score": logsource_score,
                    }
                ))
        candidates.sort(key=lambda x: x.retrieval_score, reverse=True)
        return candidates[:top_k]

    @staticmethod
    def _normalize_queries(parsed_rule: ParsedRule, query_texts: list = None) -> list:
        queries = []
        for query in [parsed_rule.normalized_rule_text, *(query_texts or [])]:
            query = (query or "").strip()
            key = query.lower()
            if query and key not in {q.lower() for q in queries}:
                queries.append(query)
        return queries or [parsed_rule.normalized_rule_text or parsed_rule.title or ""]

# Global instance will be set by AlignmentAgent
_retriever_engine = None

def retrieve_top_candidates(parsed_rule: ParsedRule, attack_index: dict, top_k: int = 10, query_texts: list = None) -> List[CandidateTechnique]:
    global _retriever_engine
    if _retriever_engine is None:
        _retriever_engine = AttackRetrieverEngine(attack_index)
    return _retriever_engine.retrieve(parsed_rule, top_k, query_texts=query_texts)
