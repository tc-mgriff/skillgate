"""
Cisco skill-scanner adapter — ADVISORY engine.

Wraps cisco-ai-skill-scanner (PyPI: cisco-ai-skill-scanner). Runs only if the
`skill-scanner` CLI is on PATH. Parses its SARIF output into the common engine
schema. Advisory: findings add to the ticket and can raise severity, never
clear a hard-reject.

Notes from the tool's own docs:
  - Primarily targets Codex/Cursor formats; Claude SKILL.md works but coverage
    may be thinner, so we pass --lenient to scan non-standard layouts.
  - It explicitly does NOT certify security; human review stays essential.
  - LLM/behavioral engines need their own API keys; we enable --use-llm and
    --enable-meta only when SKILL_SCANNER_LLM_API_KEY is present, else fall
    back to signature-only static analysis.
"""

import os
import json
import shutil
import tempfile
import subprocess

SARIF_LEVEL_TO_SEV = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW",
                      "none": "LOW"}


def is_available():
    return shutil.which("skill-scanner") is not None


def scan_tree(extracted_dir, timeout=120):
    """Run cisco skill-scanner. Returns findings in the common engine schema.
    Best-effort: if the tool errors, returns a single LOW note rather than
    failing the pipeline."""
    if not is_available():
        return []

    cmd = ["skill-scanner", "scan", extracted_dir, "--lenient",
           "--format", "sarif", "--use-behavioral"]
    if os.environ.get("SKILL_SCANNER_LLM_API_KEY"):
        cmd += ["--use-llm", "--enable-meta"]

    sarif_path = os.path.join(tempfile.mkdtemp(prefix="cisco_"), "out.sarif")
    cmd += ["--output", sarif_path]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout,
                              env={"PATH": os.environ.get("PATH", ""),
                                   "SKILL_SCANNER_LLM_API_KEY":
                                       os.environ.get("SKILL_SCANNER_LLM_API_KEY", ""),
                                   "SKILL_SCANNER_LLM_MODEL":
                                       os.environ.get("SKILL_SCANNER_LLM_MODEL", "")})
    except subprocess.TimeoutExpired:
        return [{"engine": "cisco", "severity": "LOW", "check": "CISCO_TIMEOUT",
                 "file": "(bundle)", "line": 0,
                 "message": f"Cisco scanner timed out after {timeout}s."}]

    # exit codes: non-zero often means findings, not failure; rely on SARIF.
    findings = []
    try:
        with open(sarif_path, "r", encoding="utf-8", errors="replace") as fh:
            sarif = json.load(fh)
    except (OSError, json.JSONDecodeError):
        # fall back to stdout if SARIF wasn't written
        if proc.stdout.strip():
            return [{"engine": "cisco", "severity": "LOW",
                     "check": "CISCO_RAW", "file": "(bundle)", "line": 0,
                     "message": proc.stdout.strip()[:300]}]
        return []

    for run in sarif.get("runs", []):
        for res in run.get("results", []):
            level = res.get("level", "warning")
            sev = SARIF_LEVEL_TO_SEV.get(level, "MEDIUM")
            rule = res.get("ruleId", "cisco_finding")
            msg = (res.get("message", {}) or {}).get("text", "")[:300]
            loc_file, loc_line = "(bundle)", 0
            locs = res.get("locations", [])
            if locs:
                phys = locs[0].get("physicalLocation", {})
                art = phys.get("artifactLocation", {})
                loc_file = art.get("uri", "(bundle)")
                loc_line = (phys.get("region", {}) or {}).get("startLine", 0)
            findings.append({
                "engine": "cisco", "severity": sev,
                "check": "CISCO_" + str(rule).upper()[:40],
                "file": loc_file, "line": loc_line, "message": msg})
    return findings
