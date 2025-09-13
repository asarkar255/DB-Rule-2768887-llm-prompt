from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import json
import re

app = FastAPI(
    title="LLM Prompt Builder (prefers suggestion SQL with DRAFT)"
)

# ---------- Models ----------
class InputPayload(BaseModel):
    pgm_name: str
    inc_name: str
    unit_type: str
    unit_name: str
    class_implementation: str = ""
    start_line: int = 0
    end_line: int = 0
    findings_json: str  # JSON string of findings (array)


# ---------- Helpers ----------
SQL_START_RE = re.compile(r"^\s*SELECT\b", re.IGNORECASE)
HAS_DRAFT_RE = re.compile(r"\bdraft\s*=\s*", re.IGNORECASE)

def _normalize_sql(s: str) -> str:
    """Keep original line breaks, but trim outer whitespace and collapse trailing spaces."""
    # Do not over-normalize; just strip ends
    return s.strip()

def _looks_like_sql(s: str) -> bool:
    return bool(SQL_START_RE.search(s or ""))

def _has_draft(s: str) -> bool:
    return bool(HAS_DRAFT_RE.search(s or ""))

def choose_best_sql(finding: Dict[str, Any]) -> Optional[str]:
    """
    Choose between 'suggestion' and 'snippet':
    - Prefer 'suggestion' if it looks like a full SELECT.
    - If suggestion contains a DRAFT predicate and snippet doesn't, prefer suggestion.
    - Else fallback to snippet if it looks like SQL.
    - Else fallback to non-empty suggestion.
    """
    suggestion = (finding.get("suggestion") or "").replace("\\r\\n", "\n")
    snippet = (finding.get("snippet") or "").replace("\\r\\n", "\n")

    # Decode JSON-escaped newlines if needed (works whether they are actual '\n' or escaped)
    try:
        # If strings already contain real newlines, this no-ops
        suggestion = bytes(suggestion, "utf-8").decode("unicode_escape")
        snippet = bytes(snippet, "utf-8").decode("unicode_escape")
    except Exception:
        pass

    suggestion = _normalize_sql(suggestion)
    snippet = _normalize_sql(snippet)

    sugg_is_sql = _looks_like_sql(suggestion)
    snip_is_sql = _looks_like_sql(snippet)

    # If suggestion is full SQL, prefer it
    if sugg_is_sql:
        return suggestion

    # If suggestion carries draft but snippet doesn't, prefer suggestion even if not perfect SQL
    if _has_draft(suggestion) and not _has_draft(snippet) and suggestion:
        return suggestion

    # Otherwise, fallback to snippet if it’s SQL
    if snip_is_sql:
        return snippet

    # Last resort: whichever is non-empty (prefer suggestion)
    return suggestion or snippet or None


def build_assessment(findings: List[Dict[str, Any]]) -> str:
    total = len(findings)
    with_fae = sum(1 for f in findings if "FOR ALL ENTRIES" in (f.get("snippet","") + f.get("suggestion","")).upper())
    with_draft = sum(1 for f in findings if _has_draft(f.get("snippet","")) or _has_draft(f.get("suggestion","")))
    joins = sum(1 for f in findings if " JOIN " in (f.get("snippet","") + f.get("suggestion","")).upper())

    return (
        f"Found {total} SELECT statements (joins: {joins}, FAE: {with_fae}). "
        f"{with_draft} statement(s) already include draft filtering. "
        "Prompts prefer the full suggestion SQL when available to keep injected predicates (e.g., DRAFT) intact."
    )


# ---------- API ----------
@app.post("/build-llm-prompt")
def build_llm_prompt(payload: InputPayload):
    try:
        findings = json.loads(payload.findings_json or "[]")
        if not isinstance(findings, list):
            return {
                "error": "findings_json must be a JSON array."
            }
    except json.JSONDecodeError as e:
        return {
            "error": f"findings_json is not valid JSON: {e}"
        }

    prompts: List[str] = []
    for f in findings:
        sql = choose_best_sql(f)
        if sql:
            prompts.append(sql)

    return {
        "assessment": build_assessment(findings),
        "llm_prompt": prompts
    }


@app.get("/health")
def health():
    return {"ok": True}
