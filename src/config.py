import os
from dotenv import load_dotenv

# Load .env defaults while allowing command-line/session env vars to override them.
load_dotenv(override=False)

# Project paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

SIGMA_RULES_DIR = os.path.join(DATA_DIR, "sigma_rules")
SPLUNK_RULES_DIR = os.path.join(DATA_DIR, "splunk_rules")
ATTACK_DATA_DIR = os.path.join(DATA_DIR, "attack")
OUTPUTS_DIR = os.path.join(DATA_DIR, "outputs")

RAW_ATTACK_PATH = os.path.join(ATTACK_DATA_DIR, "raw_attack.json")
ATTACK_INDEX_PATH = os.path.join(ATTACK_DATA_DIR, "attack_techniques.json")

# Retrieval / Rerank settings
TOP_K_RETRIEVAL = int(os.getenv("TOP_K_RETRIEVAL", "10"))
CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.7"))
MISMATCH_THRESHOLD = float(os.getenv("MISMATCH_THRESHOLD", "0.5"))
ABSTAIN_THRESHOLD = float(os.getenv("ABSTAIN_THRESHOLD", "0.3"))
LOGSOURCE_MATCH_WEIGHT = float(os.getenv("LOGSOURCE_MATCH_WEIGHT", "0.04"))

# Dense retrieval is optional because first-time sentence-transformers model
# loading may require network access. BM25 and heuristic retrieval remain
# available when this is disabled or model initialization fails.
ENABLE_DENSE_RETRIEVAL = os.getenv("ENABLE_DENSE_RETRIEVAL", "False").lower() == "true"
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
EMBEDDING_CACHE_DIR = os.getenv("EMBEDDING_CACHE_DIR", "")
EMBEDDING_LOCAL_FILES_ONLY = os.getenv("EMBEDDING_LOCAL_FILES_ONLY", "True").lower() == "true"

# LLM Provider settings
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai")  # openai, ollama
LLM_MODEL = os.getenv("LLM_MODEL", "qwen-plus")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_API_BASE = os.getenv("LLM_API_BASE", "")

# Fallback settings
ENABLE_LLM = os.getenv("ENABLE_LLM", "True").lower() == "true"
FALLBACK_ON_ERROR = os.getenv("FALLBACK_ON_ERROR", "True").lower() == "true"
