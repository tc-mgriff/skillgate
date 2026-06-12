# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run dev server (port 8000, auto-reload)
uvicorn app.main:app --reload --port 8000

# Run with Docker (subprocess scan mode)
docker compose up --build

# Run with hardened container scan mode
docker build -f Dockerfile.scanner -t skillgate-scanner:latest .
SKILLGATE_SCAN_MODE=container docker compose up --build
```

No test suite exists yet. Manual testing is via the upload UI at `http://localhost:8000` or via `curl -F file=@bundle.skill http://localhost:8000/upload`.

## Architecture

SkillGate is a FastAPI app that accepts uploaded Claude skill bundles (`.skill`/`.zip`/`.md`), scans them for security/hygiene issues, files a Jira ticket, then deletes all artifacts.

**Request flow:**
1. `app/main.py` — validates upload (size, extension, ZIP magic bytes), extracts to a temp dir
2. `app/extract.py` — safe ZIP extraction (rejects path traversal, symlinks, zip bombs)
3. `app/engines.py` — orchestrates all scan engines, aggregates findings, emits the gate decision
4. `app/jira_client.py` — creates the review ticket (dry-run when `JIRA_*` env vars unset)
5. `app/main.py` — deletes workdir unconditionally in `finally`

**Scan engines** (in `app/engines.py`):
- `skill_scan` (authoritative) — `scanner/skill_scan.py` via subprocess; detects injection patterns, hidden chars, broad descriptions, archive abuses
- `code` (authoritative) — `app/code_analysis.py`; AST/text analysis for eval/exec, shell-out, network, credential exfil, pickle, writes outside bundle
- `cisco` (advisory) — wraps `cisco-ai-skill-scanner` CLI if on PATH; tops out at `BLOCK_REVIEW`
- `llm` (advisory) — calls Claude on Azure AI Foundry via native Anthropic Messages API if `SKILLGATE_LLM_ENDPOINT` + key set; tops out at `BLOCK_REVIEW`

**Key invariant (enforced in `engines.py:aggregate()`):** Advisory engines can only ADD findings or RAISE the decision. They can never clear or downgrade a hard-reject from an authoritative engine. This prevents a hostile bundle from manipulating the LLM reviewer to approve itself.

**Gate tiers** (strict → lenient): `REJECT > BLOCK_REVIEW > REVIEW > PASS`

Hard-reject triggers (`REJECT`): `INJECTION_PATTERN`, `HIDDEN_CHARS`, `ARCHIVE` from `skill_scan`; and from `code`: `CODE_SHELL_DOWNLOAD_EXEC`, `CODE_OBFUSCATION`, `CODE_CODE_EXEC`, `CODE_SHELL_OUT`, `CODE_FILE_WRITE_OUTSIDE`, `CODE_DESERIALIZE`, `CODE_SECRET`, `CODE_EXFIL_PATTERN`.

**Scan worker modes** (`app/worker.py`, controlled by `SKILLGATE_SCAN_MODE`):
- `subprocess` (default/dev) — runs `scanner/skill_scan.py` in a local subprocess with a minimal env (no inherited secrets)
- `container` (prod) — runs the scanner image with `--network=none --read-only --cap-drop=ALL --memory --pids-limit`; the seam is `worker.run_scan()`

## LLM Reviewer

The LLM engine calls **Claude on Azure AI Foundry** via the **native Anthropic Messages API** (`<base>/anthropic/v1/messages`). Important:
- Do NOT use the `/openai` path or add `api-version` query params — both return 404
- `SKILLGATE_LLM_MODEL` is the Foundry **deployment name** you chose, not a dated model ID
- `max_tokens` must always be sent (Foundry requires it)
- Auth uses `x-api-key` header

## Configuration

Copy `.env.example` to `.env`. All integrations are optional and degrade gracefully:
- Jira unset → dry-run (returns the payload it would send)
- LLM vars unset → `llm` engine skipped
- `cisco-ai-skill-scanner` not on PATH → `cisco` engine skipped
