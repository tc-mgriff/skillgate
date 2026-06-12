"""
Scan worker — runs the authoritative scanner against an extracted bundle.

Two modes, selected by env SKILLGATE_SCAN_MODE:
  - "subprocess" (default, DEV): runs skill_scan.py in a local subprocess.
    Isolates the process, NOT a sandbox. Safe today only because the scanner
    just reads files.
  - "container" (PROD): runs the hardened scanner image with the bundle mounted
    read-only and the container locked down:
        --network=none      no egress
        --read-only         no writable root fs
        --tmpfs /tmp        small writable scratch only
        --memory / --cpus / --pids-limit  resource caps
        --cap-drop=ALL      no linux capabilities
        --security-opt no-new-privileges
        non-root user (baked into the image)
    The scanner's stdout (JSON) is captured; nothing the bundle contains is
    ever executed.

Both modes return the same JSON report dict, so the rest of the pipeline is
mode-agnostic.
"""

import os
import sys
import json
import subprocess

SCANNER = os.path.join(os.path.dirname(__file__), "..", "scanner", "skill_scan.py")
SCANNER_IMAGE = os.environ.get("SKILLGATE_SCANNER_IMAGE", "skillgate-scanner:latest")
MODE = os.environ.get("SKILLGATE_SCAN_MODE", "subprocess")

# resource caps for container mode
MEM = os.environ.get("SKILLGATE_SCAN_MEM", "256m")
CPUS = os.environ.get("SKILLGATE_SCAN_CPUS", "1")
PIDS = os.environ.get("SKILLGATE_SCAN_PIDS", "128")


class ScanError(Exception):
    pass


def _run_subprocess(extracted_dir, timeout):
    proc = subprocess.run(
        [sys.executable, os.path.abspath(SCANNER), extracted_dir],
        capture_output=True, text=True, timeout=timeout,
        env={"PATH": os.environ.get("PATH", "")})
    return proc.returncode, proc.stdout, proc.stderr


def _run_container(extracted_dir, timeout):
    cmd = [
        "docker", "run", "--rm",
        "--network=none",
        "--read-only",
        "--tmpfs", "/tmp:size=16m",
        "--memory", MEM,
        "--cpus", CPUS,
        "--pids-limit", PIDS,
        "--cap-drop=ALL",
        "--security-opt", "no-new-privileges",
        "-v", f"{os.path.abspath(extracted_dir)}:/scan:ro",
        SCANNER_IMAGE,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


def run_scan(extracted_dir, timeout=120):
    """Run the scanner in the configured mode. Returns the parsed report dict."""
    if not os.path.isdir(extracted_dir):
        raise ScanError(f"not a directory: {extracted_dir}")
    runner = _run_container if MODE == "container" else _run_subprocess
    try:
        code, out, err = runner(extracted_dir, timeout)
    except subprocess.TimeoutExpired as e:
        raise ScanError(f"scan timed out after {timeout}s") from e
    except FileNotFoundError as e:
        # docker missing in container mode, or python missing — be explicit
        raise ScanError(f"scan runner unavailable ({MODE} mode): {e}") from e

    # scanner exits 1 when HIGH findings exist; expected, not an error
    if code not in (0, 1):
        raise ScanError(f"scanner failed (exit {code}): {err[:500]}")
    try:
        return json.loads(out)
    except json.JSONDecodeError as e:
        raise ScanError(f"could not parse scanner output: {e}; stderr={err[:300]}") from e


# keep decide() importable from here too, so callers have one place to look
from .scan_runner import decide  # noqa: E402,F401
