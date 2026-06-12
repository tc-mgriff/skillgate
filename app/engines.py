"""
Engine aggregation + gate decision.

Engines, one decision:
  - skill_scan  (AUTHORITATIVE) — our prose/structure scanner; defines hard-reject.
  - code        (AUTHORITATIVE) — our AST/pattern code analyzer; defines hard-reject.
  - cisco       (ADVISORY)      — Cisco skill-scanner, if installed.
  - llm         (ADVISORY)      — LLM semantic reviewer, if configured.

INVARIANT: advisory engines can only ADD findings or RAISE the decision to a
stricter tier. They can NEVER clear or downgrade a hard-reject produced by an
authoritative engine. Enforced structurally: authoritative decision is computed
first, advisory findings can only move it stricter.

Both authoritative engines are our own deterministic code, so each owns a set of
hard-reject checks. Advisory engines top out at BLOCK_REVIEW so a hostile file
can't weaponize them to auto-reject benign skills.

Decision ordering (strict -> lenient): REJECT > BLOCK_REVIEW > REVIEW > PASS
"""

from .worker import run_scan, ScanError
from .scan_runner import decide as authoritative_decide
from . import cisco_adapter
from . import llm_reviewer
from . import code_analysis

ORDER = {"REJECT": 0, "BLOCK_REVIEW": 1, "REVIEW": 2, "PASS": 3}
ADVISORY_HIGH_TIER = "BLOCK_REVIEW"
ADVISORY_MED_TIER = "REVIEW"

AUTHORITATIVE_ENGINES = {"skill_scan", "code"}

# (engine, check) pairs that force an immediate REJECT. Unambiguous, deterministic
# signals only — these are not judgment calls.
HARD_REJECT = {
    ("skill_scan", "INJECTION_PATTERN"),
    ("skill_scan", "HIDDEN_CHARS"),
    ("skill_scan", "ARCHIVE"),
    ("code", "CODE_SHELL_DOWNLOAD_EXEC"),   # curl|bash
    ("code", "CODE_OBFUSCATION"),           # decoded blob -> exec (HIGH variant)
    ("code", "CODE_CODE_EXEC"),             # eval/exec/compile
    ("code", "CODE_SHELL_OUT"),             # os.system / shell=True
    ("code", "CODE_FILE_WRITE_OUTSIDE"),    # writes outside the bundle
    ("code", "CODE_DESERIALIZE"),           # pickle.loads etc.
    ("code", "CODE_SECRET"),                # embedded private key / AWS key (HIGH)
    ("code", "CODE_EXFIL_PATTERN"),         # creds + network egress in one file
}


def stricter(a, b):
    return a if ORDER[a] <= ORDER[b] else b


def _is_hard_reject(f):
    return (f.get("engine"), f.get("check")) in HARD_REJECT and f["severity"] == "HIGH"


def run_all_engines(extracted_dir):
    """Run every available engine. Returns (all_findings, engines_run)."""
    report = run_scan(extracted_dir)                 # raises ScanError on failure
    auth = authoritative_decide(report)
    for f in auth["all_findings"]:
        f.setdefault("engine", "skill_scan")

    findings = list(auth["all_findings"])
    engines_run = ["skill_scan"]

    # code analysis — always available (stdlib only), authoritative
    code_findings = code_analysis.analyze_tree(extracted_dir)
    findings += code_findings
    engines_run.append("code")

    if cisco_adapter.is_available():
        findings += cisco_adapter.scan_tree(extracted_dir)
        engines_run.append("cisco")
    if llm_reviewer.is_configured():
        findings += llm_reviewer.review_tree(extracted_dir)
        engines_run.append("llm")

    return findings, engines_run


def aggregate(extracted_dir):
    """Full multi-engine decision."""
    findings, engines_run = run_all_engines(extracted_dir)

    # 1) authoritative hard-reject from the defined (engine, check) set
    decision = "PASS"
    if any(_is_hard_reject(f) for f in findings):
        decision = "REJECT"
    else:
        # 2) authoritative non-reject HIGH -> BLOCK_REVIEW; MEDIUM -> REVIEW
        for f in findings:
            if f.get("engine") not in AUTHORITATIVE_ENGINES:
                continue
            if f["severity"] == "HIGH":
                decision = stricter(decision, "BLOCK_REVIEW")
            elif f["severity"] == "MEDIUM":
                decision = stricter(decision, "REVIEW")

    # 3) advisory escalation only — never downgrades a hard-reject
    for f in findings:
        if f.get("engine") in AUTHORITATIVE_ENGINES:
            continue
        sev = f.get("severity", "LOW")
        if sev == "HIGH":
            decision = stricter(decision, ADVISORY_HIGH_TIER)
        elif sev == "MEDIUM":
            decision = stricter(decision, ADVISORY_MED_TIER)

    summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        s = f.get("severity", "LOW")
        summary[s] = summary.get(s, 0) + 1

    return {
        "decision": decision,
        "summary": summary,
        "all_findings": findings,
        "engines_run": engines_run,
        "hard_reject": [f for f in findings if _is_hard_reject(f)],
        "block_review": [f for f in findings if f["severity"] == "HIGH"],
    }
