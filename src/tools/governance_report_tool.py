import ast
import datetime
import os
from typing import Iterable


REVIEW_ACTIONS = {
    "COARSEN_TO_PARENT",
    "REPLACE_SUSPECT",
    "REMOVE_SUSPECT",
    "ABSTAIN",
    "POSSIBLE_MISMATCH",
}

GOVERNANCE_ACTIONS = {
    "ADD_CANDIDATE",
    "REFINE_TO_SUBTECHNIQUE",
    "COARSEN_TO_PARENT",
    "REPLACE_SUSPECT",
    "REMOVE_SUSPECT",
    "SUPPLEMENT",
    "POSSIBLE_MISMATCH",
}


def parse_list_cell(value) -> list:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null"}:
        return []
    try:
        parsed = ast.literal_eval(text)
        if isinstance(parsed, list):
            return parsed
    except Exception:
        pass
    text = text.strip("[]").replace("'", "").replace('"', "")
    return [item.strip() for item in text.split(",") if item.strip()]


def truthy(value) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def build_governance_summary(records: Iterable[dict]) -> dict:
    records = list(records)
    total = len(records)
    action_counts = {}
    source_counts = {}
    review_count = 0
    low_confidence_count = 0
    suspect_remove_count = 0
    suggested_add_count = 0
    confidence_sum = 0.0

    for record in records:
        action = str(record.get("action", "") or "UNKNOWN")
        action_counts[action] = action_counts.get(action, 0) + 1
        source = str(record.get("source_type", "") or "unknown")
        source_counts[source] = source_counts.get(source, 0) + 1

        try:
            confidence = float(record.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence_sum += confidence
        if confidence < 0.5:
            low_confidence_count += 1

        suggested_add = parse_list_cell(record.get("suggested_add_tags", []))
        suspect_remove = parse_list_cell(record.get("suspect_remove_tags", []))
        suggested_add_count += len(suggested_add)
        suspect_remove_count += len(suspect_remove)

        if truthy(record.get("needs_review", False)) or action in REVIEW_ACTIONS or suspect_remove:
            review_count += 1

    governance_count = sum(action_counts.get(action, 0) for action in GOVERNANCE_ACTIONS)

    return {
        "total_rules": total,
        "source_counts": source_counts,
        "action_counts": action_counts,
        "governance_count": governance_count,
        "review_count": review_count,
        "low_confidence_count": low_confidence_count,
        "suggested_add_count": suggested_add_count,
        "suspect_remove_count": suspect_remove_count,
        "avg_confidence": confidence_sum / total if total else 0.0,
    }


def render_markdown_report(records: Iterable[dict], tactic_rows: Iterable[dict] = (), tech_rows: Iterable[dict] = ()) -> str:
    records = list(records)
    summary = build_governance_summary(records)
    generated_at = datetime.datetime.now().isoformat(timespec="seconds")

    lines = [
        "# ATT&CK Rule Governance Report",
        "",
        f"Generated: {generated_at}",
        "",
        "## Summary",
        "",
        f"- Total rules: {summary['total_rules']}",
        f"- Average confidence: {summary['avg_confidence']:.2%}",
        f"- Rules with governance actions: {summary['governance_count']}",
        f"- Rules requiring review: {summary['review_count']}",
        f"- Suggested additions: {summary['suggested_add_count']}",
        f"- Suspect removals: {summary['suspect_remove_count']}",
        "",
        "## Sources",
        "",
    ]

    for source, count in sorted(summary["source_counts"].items()):
        lines.append(f"- {source}: {count}")

    lines.extend(["", "## Actions", ""])
    for action, count in sorted(summary["action_counts"].items()):
        lines.append(f"- {action}: {count}")

    review_items = [
        record for record in records
        if truthy(record.get("needs_review", False))
        or str(record.get("action", "")) in REVIEW_ACTIONS
        or parse_list_cell(record.get("suspect_remove_tags", []))
    ]
    lines.extend(["", "## Review Queue", ""])
    if not review_items:
        lines.append("- No rules currently require analyst review.")
    else:
        for record in review_items[:50]:
            lines.append(
                f"- `{record.get('rule_id', 'unknown')}` {record.get('title', '')}: "
                f"{record.get('action', '')}, confidence={_format_conf(record.get('confidence'))}"
            )

    lines.extend(["", "## Top Techniques", ""])
    tech_rows = list(tech_rows)
    if tech_rows:
        for row in tech_rows[:15]:
            lines.append(f"- {row.get('Key')}: {row.get('Count')}")
    else:
        lines.append("- No technique coverage rows available.")

    lines.extend(["", "## Tactic Coverage", ""])
    tactic_rows = list(tactic_rows)
    if tactic_rows:
        for row in tactic_rows:
            lines.append(f"- {row.get('Key')}: {row.get('Count')}")
    else:
        lines.append("- No tactic coverage rows available.")

    return "\n".join(lines) + "\n"


def save_markdown_report(markdown: str, path: str) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(markdown)
    return path


def _format_conf(value) -> str:
    try:
        return f"{float(value):.2%}"
    except (TypeError, ValueError):
        return "n/a"

