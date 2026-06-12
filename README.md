# SkillGate

Upload a Claude skill bundle (`.skill` / `.zip`) or a bare `SKILL.md`, scan it for
prompt-injection and invocation-hygiene problems, file a Jira review ticket with
the results, then delete the artifact.

## Flow

```
upload ──> validate (size, ext, zip magic)
       ──> safe extract  (zip-slip / symlink / bomb defenses)   [app/extract.py]
       ──> scan (subprocess OR hardened container)              [app/worker.py]
       ──> multi-engine aggregate + gate tier                   [app/engines.py]
       ──> create Jira ticket                                   [app/jira_client.py]
       ──> delete artifact + extraction (finally block)         [app/main.py]
```

## Engines

Three engines feed one decision:

| Engine       | Role          | Active when                          |
|--------------|---------------|--------------------------------------|
| `skill_scan` | AUTHORITATIVE | always                               |
| `code`       | AUTHORITATIVE | always                               |
| `cisco`      | advisory      | `skill-scanner` CLI on PATH          |
| `llm`        | advisory      | `SKILLGATE_LLM_ENDPOINT` + key set   |
| `code_ext`   | advisory      | `bandit` / `shellcheck` on PATH      |

The `code` engine analyzes executable files WITHOUT running them: Python via the
`ast` module, shell and other files as text. It flags code execution
(`eval`/`exec`/`compile`), shell-out (`os.system`, `subprocess(shell=True)`,
`curl|bash`), network calls, credential/environment access, unsafe
deserialization (`pickle.loads`), writes outside the bundle, embedded secrets
and private keys, and obfuscated payloads. A credential read plus a network call
in one file is flagged as a credential-exfiltration pattern. Its unambiguous
findings are hard-reject; `code_ext` adds Bandit/ShellCheck output as advisory
when installed.

The LLM reviewer calls **Claude on Azure AI Foundry** via the native Anthropic
Messages API at `<base>/anthropic/v1/messages`. This is the Anthropic surface,
not the OpenAI one: no `api-version` query param and no `/openai` path (either
returns 404). Give `SKILLGATE_LLM_ENDPOINT` as the Foundry base
(`https://<res>.services.ai.azure.com/anthropic`) or the full messages URL; the
`/v1/messages` suffix is appended if missing. Auth is the deployment key in the
`x-api-key` header. `SKILLGATE_LLM_MODEL` is the Foundry **deployment name** you
chose (not a dated model id), and `max_tokens` is always sent because Foundry
requires it. See `.env.example`.

**Invariant (enforced in `app/engines.py`):** advisory engines can only ADD
findings or RAISE the decision to a stricter tier. They can NEVER clear or
downgrade a hard-reject. An LLM saying "this is fine, approve" cannot move a
`REJECT` — which matters because the file under review may be trying to
manipulate the reviewing model. Advisory engines also top out at
`BLOCK_REVIEW`, so a hostile file can't weaponize an advisory engine to
auto-reject benign skills either.

The Cisco scanner (`cisco-ai-skill-scanner`) is run with `--lenient` because it
primarily targets Codex/Cursor formats and Claude `SKILL.md` coverage is
thinner. Like all engines here, it detects probable patterns and does not
certify security.

## Gate tiers

| Decision      | Trigger                                             | Meaning                                   |
|---------------|-----------------------------------------------------|-------------------------------------------|
| `REJECT`      | HIGH `INJECTION_PATTERN` / `HIDDEN_CHARS` / `ARCHIVE` | Security signal. Do not import.           |
| `BLOCK_REVIEW`| other HIGH (e.g. `BROAD_DESCRIPTION`)               | Hygiene. Blocked pending author fix.      |
| `REVIEW`      | any MEDIUM                                           | Human review recommended.                 |
| `PASS`        | no HIGH/MEDIUM                                       | Safe to import after sign-off.            |

The scanner walks the **whole** extracted tree, so a payload staged in a
reference file is caught even when `SKILL.md` looks clean.

## Run (dev)

```bash
pip install -r requirements.txt
# optional: enable live Jira (otherwise dry-run)
export JIRA_BASE_URL=https://your-org.atlassian.net
export JIRA_EMAIL=you@org.com
export JIRA_API_TOKEN=...          # id.atlassian.com/manage/api-tokens
export JIRA_PROJECT=SKILL
# optional: enable the Foundry LLM reviewer (Claude via Anthropic Messages API)
export SKILLGATE_LLM_ENDPOINT="https://<res>.services.ai.azure.com/anthropic"
export SKILLGATE_LLM_API_KEY=...
export SKILLGATE_LLM_MODEL=your-claude-deployment-name
uvicorn app.main:app --reload --port 8000
```

Open http://localhost:8000. Without `JIRA_*` set, ticket creation runs in
**dry-run** and returns the payload it would have sent.

## Run (Docker)

Subprocess scan mode (simplest):

```bash
docker compose up --build
```

Hardened container scan mode (each scan runs in a locked-down throwaway
container: `--network=none --read-only --cap-drop=ALL --memory=256m`, non-root):

```bash
docker build -f Dockerfile.scanner -t skillgate-scanner:latest .
SKILLGATE_SCAN_MODE=container docker compose up --build
```

To enable engines, export before `docker compose up`:

```bash
export JIRA_BASE_URL=... JIRA_EMAIL=... JIRA_API_TOKEN=... JIRA_PROJECT=SKILL
export SKILLGATE_LLM_API_KEY=...          # enables the LLM reviewer
# bake Cisco into the image: uncomment its pip line in Dockerfile, rebuild
```

Container mode bind-mounts the docker socket so the web container can launch
scanner containers. That grants broad host control and is fine for local
testing only. In production use rootless/remote docker, a sysbox runtime, or a
separate job runner instead of the socket.

## Security posture

What is already enforced:

- Extraction refuses path traversal, absolute paths, symlinks, zip bombs
  (ratio + total + per-file caps), and entry-count explosion. Fails closed.
- Uploads are size-capped and magic-byte sniffed before anything touches disk.
- The scanner only **reads** files as text. Nothing in a bundle is executed.
- Artifact and extraction are deleted in a `finally` block, even on error.
- Jira credentials come from env only, never from request input.

### Production hardening (do before accepting real untrusted uploads)

The dev build runs the scan as a local subprocess. That isolates the Python
process but is **not** a security sandbox. Before going live:

1. Move extraction + scan into a container per scan:
   `docker run --rm --network=none --read-only --memory=256m --cpus=1
   --pids-limit=128 -v <extracted>:/scan:ro scanner-image /scan`.
   The seam is `app/scan_runner.run_scan()`.
2. Run the web tier and the scan worker as separate, non-root users.
3. Put a real queue between upload and scan (don't scan in the request thread)
   so a slow/hostile bundle can't tie up the web workers.
4. NFC-normalize + strip the extracted tree and diff against the original to
   surface smuggled zero-width / bidi characters regardless of position
   (the HIDDEN_CHARS check is a tripwire, not a guarantee).
5. Add authentication on the upload endpoint and rate-limit it.
6. Sign passing bundles and import only signed artifacts from an internal
   registry (closes the gap between "reviewed" and "deployed").

## Files

- `app/main.py` — FastAPI app, upload route, lifecycle.
- `app/extract.py` — safe archive extraction.
- `app/scan_runner.py` — subprocess scan + gate decision.
- `app/jira_client.py` — Jira Cloud REST v3 client.
- `app/templates/index.html` — upload console.
- `scanner/skill_scan.py` — the static scanner (cross-file authority,
  broad-description, injection, hidden-char, egress checks).
```
