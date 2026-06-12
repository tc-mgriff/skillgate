"""
Runs skill_scan.py over an extracted bundle and turns its JSON report into a
gate decision.

The scanner is invoked as a subprocess for isolation of the *Python process*,
not as a security sandbox. The real safety property is that skill_scan.py only
reads files as text and never executes bundle contents. For production, this
subprocess call is the seam where you swap in a container run with no network,
a read-only mount of the extracted tree, a non-root user, and cpu/mem/time
limits. See run_scan()'s docstring.
"""

import os
import sys
import json
import subprocess

SCANNER = os.path.join(os.path.dirname(__file__), "..", "scanner", "skill_scan.py")

# Gate tiers (decided in earlier design discussion):
#   HARD_REJECT  -> never import; security signal
#   BLOCK_REVIEW -> block pending human justification; hygiene signal
HARD_REJECT_CHECKS = {"INJECTION_PATTERN", "HIDDEN_CHARS", "ARCHIVE"}
# everything else that is HIGH (e.g. BROAD_DESCRIPTION) is BLOCK_REVIEW


class ScanError(Exception):
    pass


def run_scan(extracted_dir, timeout=60):
    """Run the scanner on a directory. Returns the parsed report dict.

    PRODUCTION HARDENING (replace this subprocess call):
      docker run --rm --network=none --read-only \
        --memory=256m --cpus=1 --pids-limit=128 \
        -v <extracted_dir>:/scan:ro scanner-image /scan
    Keep the no-network + read-only + non-root invariants; the scanner needs
    only read access and no egress.
    """
    if not os.path.isdir(extracted_dir):
        raise ScanError(f"not a directory: {extracted_dir}")
    try:
        proc = subprocess.run(
            [sys.executable, os.path.abspath(SCANNER), extracted_dir],
            capture_output=True, text=True, timeout=timeout,
            # minimal env; no inherited secrets reach the scan
            env={"PATH": os.environ.get("PATH", "")},
        )
    except subprocess.TimeoutExpired as e:
        raise ScanError(f"scan timed out after {timeout}s") from e

    # scanner exits 1 when HIGH findings exist; that is expected, not an error
    if proc.returncode not in (0, 1):
        raise ScanError(
            f"scanner failed (exit {proc.returncode}): {proc.stderr[:500]}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise ScanError(f"could not parse scanner output: {e}") from e


def decide(report):
    """Map a scan report to a gate decision dict."""
    findings = report.get("findings", [])
    hard = [f for f in findings
            if f["severity"] == "HIGH" and f["check"] in HARD_REJECT_CHECKS]
    block = [f for f in findings
             if f["severity"] == "HIGH" and f["check"] not in HARD_REJECT_CHECKS]

    if hard:
        decision = "REJECT"
    elif block:
        decision = "BLOCK_REVIEW"
    elif report.get("summary", {}).get("MEDIUM", 0) > 0:
        decision = "REVIEW"
    else:
        decision = "PASS"

    return {
        "decision": decision,
        "hard_reject": hard,
        "block_review": block,
        "summary": report.get("summary", {}),
        "all_findings": findings,
    }
