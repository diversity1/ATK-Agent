from parsers.sigma_adapter import SigmaAdapter
from parsers.splunk_adapter import SplunkAdapter


_ADAPTERS = {
    "sigma": SigmaAdapter(),
    "splunk": SplunkAdapter(),
}


def get_rule_adapter(source_type: str):
    key = (source_type or "sigma").strip().lower()
    if key not in _ADAPTERS:
        raise ValueError(f"Unsupported rule source_type: {source_type}")
    return _ADAPTERS[key]

