import re
from typing import List
from core.schemas import ParsedRule, CandidateTechnique
from knowledge.datasource_ontology import build_ir_hints
from tools.tag_validator_tool import check_parent_child_relation, is_valid_attack_tag, normalize_attack_tag
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
        hints.extend(build_ir_hints(getattr(parsed_rule, "rule_ir", None)))
        for telemetry in getattr(parsed_rule, "telemetry", []) or []:
            hints.append((telemetry, 0.45))
        for component in getattr(parsed_rule, "data_components", []) or []:
            hints.append((component, 0.35))
        for platform in getattr(parsed_rule, "platforms", []) or []:
            hints.append((platform, 0.20))

        for field in ("product", "category", "service"):
            value = self._normalize_logsource_value(getattr(parsed_rule, field, ""))
            if not value:
                continue
            hints.append((value.replace("_", " "), 0.10))
            hints.extend(LOGSOURCE_HINTS.get(f"{field}:{value}", []))

        for event_id in re.findall(r"\b\d{3,5}\b", parsed_rule.detection_text or ""):
            hints.append((event_id, 0.12))
        for observable in getattr(parsed_rule, "observables", []) or []:
            if observable.get("type") == "event_id":
                hints.append((str(observable.get("value", "")), 0.12))

        deduped = {}
        for term, weight in hints:
            term = str(term).strip().lower()
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

        rule_platforms = {
            self._normalize_logsource_value(platform)
            for platform in (getattr(parsed_rule, "platforms", []) or [])
        }
        product = self._normalize_logsource_value(parsed_rule.product)
        platforms = {str(p).lower() for p in doc.get("platforms", []) or []}
        if rule_platforms and platforms.intersection(rule_platforms):
            score += 0.20
        elif product == "windows" and "windows" in platforms:
            score += 0.20
        elif product == "linux" and "linux" in platforms:
            score += 0.20
        elif product and product in platforms:
            score += 0.20

        return min(1.0, score)

    def _compute_candidate_evidence(self, parsed_rule: ParsedRule, tid: str, doc: dict) -> dict:
        doc_text = self._doc_full_text(doc)
        data_source_text = self._doc_data_source_text(doc)

        matched_observables = []
        matched_values = set()
        for observable in getattr(parsed_rule, "observables", []) or []:
            value = self._normalize_match_value(observable.get("value", ""))
            if len(value) < 2:
                continue
            if self._value_matches_doc(value, doc_text):
                matched_observables.append(observable)
                matched_values.add(value)

        entity_values = [
            self._normalize_match_value(entity)
            for entity in (getattr(parsed_rule, "entities", []) or [])
        ]
        entity_values = [value for value in entity_values if len(value) >= 2]
        matched_entities = {value for value in entity_values if self._value_matches_doc(value, doc_text)}
        entity_denominator = max(1, min(6, len(set(entity_values))))
        entity_score = min(1.0, len(matched_entities.union(matched_values)) / entity_denominator)

        rule_data_terms = self._dedupe_texts([
            *(getattr(parsed_rule, "telemetry", []) or []),
            *(getattr(parsed_rule, "data_components", []) or []),
        ])
        matched_data_sources = [
            term for term in rule_data_terms
            if self._normalize_match_value(term) in data_source_text
        ]
        telemetry_denominator = max(1, min(6, len(rule_data_terms)))
        telemetry_score = min(1.0, len(matched_data_sources) / telemetry_denominator)

        rule_platforms = {
            self._normalize_logsource_value(platform)
            for platform in (getattr(parsed_rule, "platforms", []) or [])
            if platform
        }
        doc_platforms = {
            self._normalize_logsource_value(platform)
            for platform in (doc.get("platforms", []) or [])
            if platform
        }
        platform_score = 0.0
        contradictions = []
        if rule_platforms and doc_platforms:
            if rule_platforms.intersection(doc_platforms):
                platform_score = 1.0
            else:
                contradictions.append(
                    "Rule platform does not overlap with ATT&CK candidate platforms."
                )

        inferred_tactics = self._infer_rule_tactics(parsed_rule)
        doc_tactics = {str(tactic).lower() for tactic in doc.get("tactics", []) or []}
        tactic_score = 0.0
        if inferred_tactics and doc_tactics:
            tactic_score = 1.0 if inferred_tactics.intersection(doc_tactics) else 0.0

        existing_tag_score = self._existing_tag_score(tid, getattr(parsed_rule, "existing_attack_tags", []) or [])

        contradiction_penalty = 0.0
        if contradictions:
            contradiction_penalty += 1.0
        if rule_data_terms and not matched_data_sources:
            contradiction_penalty += 0.25

        score_breakdown = {
            "entity_score": round(entity_score, 4),
            "telemetry_score": round(telemetry_score, 4),
            "platform_score": round(platform_score, 4),
            "tactic_score": round(tactic_score, 4),
            "existing_tag_score": round(existing_tag_score, 4),
            "contradiction_penalty": round(min(1.0, contradiction_penalty), 4),
        }
        evidence_bonus = (
            0.030 * entity_score
            + 0.040 * telemetry_score
            + 0.020 * platform_score
            + 0.015 * tactic_score
            + 0.020 * existing_tag_score
            - 0.035 * min(1.0, contradiction_penalty)
        )
        score_breakdown["evidence_bonus"] = round(evidence_bonus, 4)

        return {
            "score_breakdown": score_breakdown,
            "matched_observables": matched_observables[:10],
            "matched_data_sources": matched_data_sources,
            "contradictions": contradictions,
            "evidence_bonus": evidence_bonus,
        }

    @staticmethod
    def _doc_full_text(doc: dict) -> str:
        parts = [
            doc.get("id", ""),
            doc.get("name", ""),
            doc.get("description", ""),
            doc.get("detection", ""),
            " ".join(doc.get("tactics", []) or []),
            " ".join(doc.get("platforms", []) or []),
            " ".join(doc.get("data_sources", []) or []),
        ]
        for item in doc.get("log_sources", []) or []:
            if isinstance(item, dict):
                parts.extend(str(item.get(field, "")) for field in ("component", "name", "channel"))
            else:
                parts.append(str(item))
        return " ".join(str(part) for part in parts if part).lower()

    @staticmethod
    def _normalize_match_value(value) -> str:
        text = str(value or "").strip().lower()
        text = text.strip('"').strip("'")
        text = re.sub(r"^[*%]+|[*%]+$", "", text)
        text = text.replace("\\\\", "\\")
        if "\\" in text and not text.endswith("\\"):
            tail = text.rsplit("\\", 1)[-1]
            if "." in tail and len(tail) > 2:
                return tail
        return text

    @staticmethod
    def _value_matches_doc(value: str, doc_text: str) -> bool:
        if not value:
            return False
        alternatives = {value}
        if value.endswith(".exe"):
            alternatives.add(value[:-4])
        if value.startswith("-") and len(value) > 1:
            alternatives.add(value[1:])
        if value.startswith("/") and len(value) > 1:
            alternatives.add(value[1:])
        return any(alt and alt in doc_text for alt in alternatives)

    @staticmethod
    def _dedupe_texts(values: list) -> list:
        seen = set()
        result = []
        for value in values:
            text = str(value or "").strip()
            key = text.lower()
            if text and key not in seen:
                seen.add(key)
                result.append(text)
        return result

    @staticmethod
    def _infer_rule_tactics(parsed_rule: ParsedRule) -> set:
        text = " ".join([
            parsed_rule.title or "",
            parsed_rule.description or "",
            parsed_rule.normalized_rule_text or "",
        ]).lower()
        tactic_rules = [
            ("credential-access", ["lsass", "mimikatz", "credential", "dump", "password"]),
            ("execution", ["powershell", "cmd", "script", "execute", "process creation"]),
            ("defense-evasion", ["encoded", "obfuscat", "bypass", "rundll32", "regsvr32"]),
            ("persistence", ["schtasks", "scheduled task", "run key", "startup", "service creation"]),
            ("discovery", ["whoami", "net user", "systeminfo", "query", "enumerat"]),
            ("command-and-control", ["network connection", "dns", "http", "callback", "beacon"]),
            ("lateral-movement", ["remote service", "psexec", "wmic", "winrm"]),
        ]
        return {
            tactic for tactic, keywords in tactic_rules
            if any(keyword in text for keyword in keywords)
        }

    @staticmethod
    def _existing_tag_score(tid: str, existing_tags: list) -> float:
        if not is_valid_attack_tag(tid):
            return 0.0
        normalized_tid = normalize_attack_tag(tid)
        for tag in existing_tags:
            if not is_valid_attack_tag(tag):
                continue
            normalized_tag = normalize_attack_tag(tag)
            if normalized_tag == normalized_tid:
                return 1.0
            if check_parent_child_relation(normalized_tag, normalized_tid) or check_parent_child_relation(normalized_tid, normalized_tag):
                return 0.5
        return 0.0

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
            evidence = self._compute_candidate_evidence(parsed_rule, tid, self.attack_index[tid])
            rrf_scores[idx] += evidence["evidence_bonus"]
                
        final_ranks = np.argsort(rrf_scores)[::-1][:top_k]
        
        candidates = []
        for idx in final_ranks:
            tid = self.keys[idx]
            doc = self.attack_index[tid]
            score = rrf_scores[idx]
            evidence = self._compute_candidate_evidence(parsed_rule, tid, doc)
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
            why["score_breakdown"] = evidence["score_breakdown"]
            why["matched_data_sources"] = evidence["matched_data_sources"]
            why["contradictions"] = evidence["contradictions"]
            candidates.append(CandidateTechnique(
                technique_id=tid,
                technique_name=doc.get("name", ""),
                retrieval_score=float(score),
                tactics=doc.get("tactics", []),
                platforms=doc.get("platforms", []),
                why=why,
                score_breakdown=evidence["score_breakdown"],
                matched_observables=evidence["matched_observables"],
                matched_data_sources=evidence["matched_data_sources"],
                contradictions=evidence["contradictions"],
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
                
            doc_platforms = {p.lower() for p in doc.get("platforms", [])}
            rule_platforms = {p.lower() for p in (getattr(parsed_rule, "platforms", []) or [])}
            if rule_platforms:
                p_score = 0.5 if doc_platforms.intersection(rule_platforms) else 0.0
            else:
                p_score = 0.5 if parsed_rule.product.lower() in doc_platforms else 0.0
            h_score = 0.05 if tid in parsed_rule.existing_attack_tags else 0.0
            logsource_score = self._compute_logsource_score(parsed_rule, doc)
            evidence = self._compute_candidate_evidence(parsed_rule, tid, doc)
            breakdown = evidence["score_breakdown"]
            evidence_score = (
                0.25 * breakdown.get("entity_score", 0.0)
                + 0.35 * breakdown.get("telemetry_score", 0.0)
                + 0.15 * breakdown.get("platform_score", 0.0)
                + 0.10 * breakdown.get("tactic_score", 0.0)
                + 0.10 * breakdown.get("existing_tag_score", 0.0)
                - 0.20 * breakdown.get("contradiction_penalty", 0.0)
            )
            
            total_score = t_score + p_score + h_score + (0.5 * logsource_score) + evidence_score
            if total_score > 0:
                candidates.append(CandidateTechnique(
                    technique_id=tid, technique_name=doc.get("name", ""), retrieval_score=total_score,
                    tactics=doc.get("tactics", []), platforms=doc.get("platforms", []),
                    why={
                        "text_score": t_score,
                        "platform_score": p_score,
                        "hint_score": h_score,
                        "logsource_score": logsource_score,
                        "score_breakdown": evidence["score_breakdown"],
                        "matched_data_sources": evidence["matched_data_sources"],
                        "contradictions": evidence["contradictions"],
                    },
                    score_breakdown=evidence["score_breakdown"],
                    matched_observables=evidence["matched_observables"],
                    matched_data_sources=evidence["matched_data_sources"],
                    contradictions=evidence["contradictions"],
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
