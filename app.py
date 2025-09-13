from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import json
import re
from datetime import date

app = FastAPI(
    title="LLM Prompt Builder (with explicit request + prefers suggestion SQL with DRAFT)"
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
    # Optional: extra rules you want to inject into the request
    extra_policy_bullets: Optional[List[str]] = None


# ---------- Helpers ----------
SQL_START_RE = re.compile(r"^\s*SELECT\b", re.IGNORECASE)
HAS_DRAFT_RE = re.compile(r"\bdraft\s*=\s*", re.IGNORECASE)

def _normalize_sql(s: str) -> str:
    """Keep original line breaks, but trim outer whitespace and collapse trailing spaces."""
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

    # Decode JSON-escaped sequences if present; safe if not
    try:
        suggestion = bytes(suggestion, "utf-8").decode("unicode_escape")
        snippet = bytes(snippet, "utf-8").decode("unicode_escape")
    except Exception:
        pass

    suggestion = _normalize_sql(suggestion)
    snippet = _normalize_sql(snippet)

    sugg_is_sql = _looks_like_sql(suggestion)
    snip_is_sql = _looks_like_sql(snippet)

    if sugg_is_sql:
        return suggestion
    if _has_draft(suggestion) and not _has_draft(snippet) and suggestion:
        return suggestion
    if snip_is_sql:
        return snippet
    return suggestion or snippet or None


def build_assessment(findings: List[Dict[str, Any]]) -> str:
    total = len(findings)
    text_blob = " ".join([(f.get("snippet", "") or "") + " " + (f.get("suggestion", "") or "") for f in findings]).upper()
    with_fae = text_blob.count("FOR ALL ENTRIES")
    with_draft = len([1 for f in findings if _has_draft(f.get("snippet","")) or _has_draft(f.get("suggestion",""))])
    joins = text_blob.count(" JOIN ")
    return (
        f"Found {total} SELECT statements (joins: {joins}, FAE: {with_fae}). "
        f"{with_draft} statement(s) include draft filtering. "
        "Prompts prefer the full suggestion SQL when available to keep injected predicates (e.g., DRAFT) intact."
    )


def default_policy_bullets(today_str: str) -> List[str]:
    """
    Baseline rules to tell the LLM exactly what to do with the ABAP.
    You can extend/override by passing extra_policy_bullets in the request.
    """
    return [
        "Remediate the ABAP code EXACTLY following these bullets.",
        "Apply conditional rules (e.g., draft/active predicates) ONLY when the relevant columns exist in the referenced tables/views.",
        "For SELECTs reading VBRP/VBRK in this customer landscape, append 'AND b~draft = space' and 'AND c~draft = space' (or matching aliases) when those columns exist.",
        "Avoid SELECT *; use explicit field lists. Keep S/4HANA Open SQL syntax (comma-separated field lists, @ host-variable escapes).",
        "Do NOT add ORDER BY to SELECT SINGLE. For top-1 by criterion, use 'ORDER BY ... UP TO 1 ROWS'.",
        "When FOR ALL ENTRIES is used, guard with 'IF it[] IS NOT INITIAL.' and deduplicate keys before FAE.",
        "Keep behavior the same unless bullets say otherwise. Do not suppress warnings or add pseudo-comments.",
        f"Every ADDED or MODIFIED line must end with an inline ABAP comment: \" Added By Pwc{today_str}",
        "Output ONLY strict JSON with key: { \"remediated_code\": \"<full updated ABAP code with PwC comments on added/modified lines>\" }",
    ]


def build_request_text(payload: InputPayload, bullets: List[str]) -> str:
    """
    Compose the explicit 'what to do' request for the LLM,
    including program context + rules bullets.
    """
    ctx = (
        f"Context:\n"
        f"- Program: {payload.pgm_name}\n"
        f"- Include: {payload.inc_name}\n"
        f"- Unit type: {payload.unit_type}\n"
        f"- Unit name: {payload.unit_name}\n"
    )
    # Turn bullets into a clean list block
    bullets_text = "\n".join([f"- {b}" for b in bullets])
    return (
        f"Remediate the ABAP code shown below.\n\n"
        f"{ctx}\n"
        f"Rules you MUST follow:\n{bullets_text}\n\n"
        f"Use the SQL snippets in 'llm_prompt' as the canonical SELECT sources where applicable."
    )


# ---------- API ----------
@app.post("/build-llm-prompt")
def build_llm_prompt(payload: InputPayload):
    try:
        findings = json.loads(payload.findings_json or "[]")
        if not isinstance(findings, list):
            return {"error": "findings_json must be a JSON array."}
    except json.JSONDecodeError as e:
        return {"error": f"findings_json is not valid JSON: {e}"}

    prompts: List[str] = []
    for f in findings:
        sql = choose_best_sql(f)
        if sql:
            prompts.append(sql)

    today_str = date.today().strftime("%Y-%m-%d")
    bullets = default_policy_bullets(today_str)
    if payload.extra_policy_bullets:
        bullets.extend(payload.extra_policy_bullets)

    return {
        "assessment": build_assessment(findings),
        "request": build_request_text(payload, bullets),
        "llm_prompt": prompts
    }


@app.get("/health")
def health():
    return {"ok": True}
