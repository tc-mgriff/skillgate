"""
SkillGate - FastAPI app for reviewing uploaded skill bundles.

Flow:
  1. Accept upload (.skill / .zip, or a bare SKILL.md).
  2. Enforce upload-side limits (size, extension, content-type sniff).
  3. Extract safely (app/extract.py) into a per-request temp dir.
  4. Scan the tree (scanner/skill_scan.py via app/scan_runner.py).
  5. Create a Jira review ticket (app/jira_client.py).
  6. Delete the artifact AND the extracted tree (per design: delete after scan).

Security posture (dev):
  - The scan worker runs as a subprocess; the real isolation property is that
    the scanner only READS files. Nothing in the bundle is executed.
  - For production: move steps 3-4 into a container with --network=none,
    read-only FS, non-root, and cpu/mem/pids/time limits. The seam is
    app/scan_runner.run_scan().
  - Uploads never reach the filesystem outside a randomized temp dir, and are
    removed in a finally block even on error.
"""

import os
import shutil
import hashlib
import tempfile

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .extract import safe_extract_zip, UnsafeArchive, OversizedArchive
from .worker import ScanError
from .engines import aggregate
from . import jira_client

MAX_UPLOAD_BYTES = 25 * 1024 * 1024          # 25 MB hard cap on the upload
ALLOWED_EXT = {".skill", ".zip", ".md"}
ZIP_MAGIC = b"PK\x03\x04"                     # local file header

BASE_DIR = os.path.dirname(__file__)
app = FastAPI(title="SkillGate", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")),
          name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        context={"jira_configured": jira_client.is_configured()})


def _safe_ext(filename):
    _, ext = os.path.splitext(filename or "")
    ext = ext.lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(400, f"unsupported file type: {ext or 'none'}")
    return ext


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    ext = _safe_ext(file.filename)

    # read with a hard cap so a huge upload can't exhaust memory/disk
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "upload exceeds size limit")
    if not data:
        raise HTTPException(400, "empty upload")

    # content sniff: zip-family extensions must actually be zips
    if ext in (".skill", ".zip") and not data.startswith(ZIP_MAGIC):
        raise HTTPException(400, "file is not a valid zip archive")

    sha256 = hashlib.sha256(data).hexdigest()

    workdir = tempfile.mkdtemp(prefix="skillgate_")
    try:
        if ext == ".md":
            # bare SKILL.md: drop it into an extracted-style tree
            extracted = os.path.join(workdir, "extracted")
            os.makedirs(extracted, exist_ok=True)
            with open(os.path.join(extracted, "SKILL.md"), "wb") as fh:
                fh.write(data)
            file_count = 1
        else:
            artifact = os.path.join(workdir, "bundle.zip")
            with open(artifact, "wb") as fh:
                fh.write(data)
            extracted = os.path.join(workdir, "extracted")
            try:
                result = safe_extract_zip(artifact, extracted)
                file_count = result.file_count
            except OversizedArchive as e:
                # Resource limit — not a security signal; submit for review with a note
                meta = {"filename": file.filename, "sha256": sha256,
                        "upload_bytes": data}
                archive_finding = {
                    "severity": "MEDIUM", "check": "ARCHIVE_SIZE",
                    "file": file.filename or "bundle", "line": 0,
                    "message": f"Bundle exceeds processing limit: {e}. "
                               "A reviewer will need to inspect this manually."}
                decision = {
                    "decision": "REVIEW",
                    "hard_reject": [],
                    "block_review": [],
                    "summary": {"HIGH": 0, "MEDIUM": 1, "LOW": 0},
                    "all_findings": [archive_finding],
                }
                ticket = jira_client.create_ticket(meta, decision)
                return JSONResponse(content={
                    "decision": "REVIEW",
                    "findings": decision["all_findings"],
                    "summary": decision["summary"],
                    "sha256": sha256, "jira": ticket})
            except UnsafeArchive as e:
                # Genuine security signal — reject and track in Jira
                meta = {"filename": file.filename, "sha256": sha256,
                        "upload_bytes": data}
                archive_finding = {
                    "severity": "HIGH", "check": "ARCHIVE",
                    "file": file.filename or "bundle", "line": 0,
                    "message": f"Unsafe archive: {e}"}
                decision = {
                    "decision": "REJECT",
                    "hard_reject": [archive_finding],
                    "block_review": [],
                    "summary": {"HIGH": 1, "MEDIUM": 0, "LOW": 0},
                    "all_findings": [archive_finding],
                }
                ticket = jira_client.create_ticket(meta, decision)
                return JSONResponse(status_code=422, content={
                    "decision": "REJECT",
                    "findings": decision["all_findings"],
                    "summary": decision["summary"],
                    "sha256": sha256, "jira": ticket})

        # scan + decide (multi-engine)
        try:
            decision = aggregate(extracted)
        except ScanError as e:
            raise HTTPException(500, f"scan failed: {e}")

        # read SKILL.md content for the ticket before the workdir is deleted
        skill_path = os.path.join(extracted, "SKILL.md")
        skill_content = None
        if os.path.isfile(skill_path):
            try:
                with open(skill_path, "r", encoding="utf-8", errors="replace") as fh:
                    skill_content = fh.read(8000)  # cap to keep ticket size sane
            except OSError:
                pass

        meta = {"filename": file.filename, "sha256": sha256,
                "file_count": file_count, "skill_content": skill_content,
                "upload_bytes": data}
        ticket = jira_client.create_ticket(meta, decision)

        return JSONResponse({
            "decision": decision["decision"],
            "summary": decision["summary"],
            "findings": decision["all_findings"],
            "engines_run": decision.get("engines_run", []),
            "sha256": sha256,
            "file_count": file_count,
            "jira": ticket,
        })
    finally:
        # delete artifact AND extraction unconditionally (design: delete after scan)
        shutil.rmtree(workdir, ignore_errors=True)


@app.get("/healthz")
async def healthz():
    return {"ok": True, "jira_configured": jira_client.is_configured()}
