from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import date
import re

app = FastAPI(
    title="LLM Prompt Builder (array in -> array out; request embedded in llm_prompt string)"
)

# -----------------------------
# Pydantic models (INPUT/OUTPUT)
# -----------------------------
class FindingIn(BaseModel):
    pgm_name: Optional[str] = ""
    inc_name: Optional[str] = ""
    type: Optional[str] = ""
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    issue_type: Optional[str] = ""
    severity: Optional[str] = ""
    message: Optional[str] = ""
    suggestion: Optional[str] = ""
    snippet: Optional[str] = ""

class UnitIn(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    start_line: int = 0
    end_line: int = 0
    findings: List[FindingIn] = []

class UnitOut(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    start_line: int = 0
    end_line: int = 0
    assessment: str
    llm_prompt: str


# -----------------------------
# Helpers
# -----------------------------
SQL_START_RE = re.compile(r"^\s*SELECT\b", re.IGNORECASE | re.DOTALL)
HAS_DRAFT_RE = re.compile(r"\bdraft\s*=\s*", re.IGNORECASE)

def _normalize_text(s: Optional[str]) -> str:
    if not s:
        return ""
    # Keep line breaks, trim outer whitespace
    return s.replace("\\r\\n", "\n").strip()

def _looks_like_sql(s: str) -> bool:
    return bool(SQL_START_RE.search(s or ""))

def _has_draft(s: str) -> bool:
    return bool(HAS_DRAFT_RE.search(s or ""))

def choose_best_sql(f: FindingIn) -> Optional[str]:
    """
    Prefer full SELECTs that include DRAFT predicates.
    Priority:
    1) suggestion if it looks like SELECT
    2) suggestion if it has DRAFT and snippet doesn't
    3) snippet if it looks like SELECT
    4) otherwise any non-empty suggestion/snippet
    """
    suggestion = _normalize_text(f.suggestion)
    snippet = _normalize_text(f.snippet)

    sugg_is_sql = _looks_like_sql(suggestion)
    snip_is_sql = _looks_like_sql(snippet)

    if sugg_is_sql:
        return suggestion
    if _has_draft(suggestion) and not _has_draft(snippet) and suggestion:
        return suggestion
    if snip_is_sql:
        return snippet
    return suggestion or snippet or None

def build_assessment(findings: List[FindingIn]) -> str:
    total = len(findings)
    blob = " ".join([(f.snippet or "") + " " + (f.suggestion or "") for f in findings]).upper()
    joins = blob.count(" JOIN ")
    with_fae = blob.count("FOR ALL ENTRIES")
    with_draft = sum(1 for f in findings if _has_draft(f.snippet or "") or _has_draft(f.suggestion or ""))
    return (
        f"Found {total} finding(s) (joins: {joins}, FAE: {with_fae}). "
        f"{with_draft} statement(s) include draft filtering. "
        "The prompt embeds clear remediation instructions followed by canonical SQL snippets (preferring ones with DRAFT filters)."
    )

def default_policy_bullets(today_str: str) -> List[str]:
    return [
        "Remediate the ABAP code EXACTLY following these bullets.",
        "Apply conditional rules (e.g., draft/active predicates) ONLY when the relevant columns exist in the referenced tables/views.",
        "For SELECTs reading VBRP/VBRK in this customer landscape, append 'AND b~draft = space' and 'AND c~draft = space' (or matching aliases) when those columns exist.",
        "Avoid SELECT *; use explicit field lists. Keep S/4HANA Open SQL syntax (comma-separated field lists, @ host-variable escapes).",
        "Do NOT add ORDER BY to SELECT SINGLE. For top-1 by criterion, use 'ORDER BY … UP TO 1 ROWS'.",
        "When FOR ALL ENTRIES is used, guard with 'IF it[] IS NOT INITIAL.' and deduplicate keys before FAE.",
        "Keep behavior the same unless bullets say otherwise. Do not suppress warnings or add pseudo-comments.",
        f"Every ADDED or MODIFIED line must end with an inline ABAP comment: \" Added By Pwc{today_str}",
        "Return ONLY strict JSON with key { \"remediated_code\": \"<full updated ABAP code with PwC comments on added/modified lines>\" }.",
    ]

def build_request_text(unit: UnitIn, bullets: List[str]) -> str:
    ctx = (
        f"Context:\n"
        f"- Program: {unit.pgm_name}\n"
        f"- Include: {unit.inc_name}\n"
        f"- Unit type: {unit.type}\n"
        f"- Unit name: {unit.name or ''}\n"
    )
    bullets_text = "\n".join([f"- {b}" for b in bullets])
    return (
        "Remediate the ABAP code shown below.\n\n"
        f"{ctx}\n"
        "Rules you MUST follow:\n"
        f"{bullets_text}\n\n"
        "Use the SQL snippets below as the canonical SELECT sources where applicable."
    )

def compose_llm_prompt(unit: UnitIn, findings: List[FindingIn]) -> str:
    today_str = date.today().strftime("%Y-%m-%d")
    bullets = default_policy_bullets(today_str)
    request_text = build_request_text(unit, bullets)

    # Build unique SQL snippets (prefer suggestions that keep DRAFT)
    seen: set = set()
    chosen_snippets: List[str] = []
    for f in findings:
        sql = choose_best_sql(f)
        if not sql:
            continue
        key = sql.strip().upper()
        if key in seen:
            continue
        seen.add(key)
        chosen_snippets.append(sql)

    snippets_block = ""
    if chosen_snippets:
        blocks = []
        for sql in chosen_snippets:
            # Present as ABAP code fence for clarity inside a single prompt string
            blocks.append(f"```abap\n{sql}\n```")
        snippets_block = "\n\nSQL snippets to apply (prefer those with DRAFT filters):\n\n" + "\n\n".join(blocks) + "\n"

    return request_text + ("\n\n" + snippets_block if snippets_block else "\n")

# -----------------------------
# API
# -----------------------------
@app.post("/build-llm-prompt", response_model=List[UnitOut])
def build_llm_prompt(units: List[UnitIn]):
    """
    Input: Array of units with 'findings' (as provided by the caller).
    Output: Array of units with 'assessment' and a single-string 'llm_prompt'
            that embeds (1) the explicit request and (2) the selected SQL snippets.
    """
    results: List[UnitOut] = []
    for unit in units:
        assessment = build_assessment(unit.findings or [])
        llm_prompt = compose_llm_prompt(unit, unit.findings or [])

        results.append(UnitOut(
            pgm_name=unit.pgm_name,
            inc_name=unit.inc_name,
            type=unit.type,
            name=unit.name or "",
            class_implementation=unit.class_implementation or "",
            start_line=unit.start_line or 0,
            end_line=unit.end_line or 0,
            assessment=assessment,
            llm_prompt=llm_prompt
        ))
    return results

@app.get("/health")
def health():
    return {"ok": True}
