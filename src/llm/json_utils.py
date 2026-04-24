import json
import re


def parse_json_object(raw_text: str) -> dict:
    if not raw_text:
        return {}

    try:
        data = json.loads(raw_text)
        return data if isinstance(data, dict) else {}
    except Exception:
        pass

    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        try:
            data = json.loads(fenced.group(1))
            return data if isinstance(data, dict) else {}
        except Exception:
            pass

    start = raw_text.find("{")
    end = raw_text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            data = json.loads(raw_text[start:end + 1])
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    return {}
