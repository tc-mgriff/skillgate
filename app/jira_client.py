"""
Jira Cloud REST v3 client. Creates a review ticket summarizing a scan.

Credentials come from environment ONLY, never from request input:
  JIRA_BASE_URL   e.g. https://your-org.atlassian.net
  JIRA_EMAIL      the account email tied to the API token
  JIRA_API_TOKEN  an Atlassian API token (id.atlassian.com/manage/api-tokens)
  JIRA_PROJECT    project key, e.g. SKILL

If any are missing the app runs in dry-run mode and returns the payload it
WOULD have sent, so you can develop without live Jira. Auth is HTTP Basic with
email:token over HTTPS, per Atlassian's documented scheme for Jira Cloud.
"""

import os
import json
import base64
import urllib.request
import urllib.error

DECISION_LABEL = {
    "REJECT": "skillgate-reject",
    "BLOCK_REVIEW": "skillgate-block",
    "REVIEW": "skillgate-review",
    "PASS": "skillgate-pass",
}


def _env():
    return {
        "base": os.environ.get("JIRA_BASE_URL", "").rstrip("/"),
        "email": os.environ.get("JIRA_EMAIL", ""),
        "token": os.environ.get("JIRA_API_TOKEN", ""),
        "project": os.environ.get("JIRA_PROJECT", ""),
    }


def is_configured():
    e = _env()
    return all([e["base"], e["email"], e["token"], e["project"]])


def _adf_paragraph(text):
    """Atlassian Document Format paragraph node."""
    return {"type": "paragraph",
            "content": [{"type": "text", "text": text}]}


def _build_description(meta, decision):
    """Build an ADF doc body summarizing the scan."""
    nodes = [
        _adf_paragraph(f"Uploaded bundle: {meta.get('filename', 'unknown')}"),
        _adf_paragraph(f"SHA-256: {meta.get('sha256', 'n/a')}"),
        _adf_paragraph(f"Decision: {decision['decision']}"),
        _adf_paragraph(
            "Summary - HIGH: {HIGH}  MEDIUM: {MEDIUM}  LOW: {LOW}".format(
                HIGH=decision["summary"].get("HIGH", 0),
                MEDIUM=decision["summary"].get("MEDIUM", 0),
                LOW=decision["summary"].get("LOW", 0))),
    ]
    skill_content = meta.get("skill_content")
    if skill_content:
        nodes.append(_adf_paragraph("SKILL.md:"))
        nodes.append({
            "type": "codeBlock",
            "attrs": {"language": "markdown"},
            "content": [{"type": "text", "text": skill_content}],
        })

    findings = decision["all_findings"]
    if findings:
        nodes.append(_adf_paragraph("Findings:"))
        items = []
        for f in findings[:50]:  # cap ticket size
            line = (f"[{f['severity']}] {f['check']} - "
                    f"{os.path.basename(f['file'])}:{f['line']} - {f['message']}")
            items.append({"type": "listItem",
                          "content": [_adf_paragraph(line)]})
        nodes.append({"type": "bulletList", "content": items})
        if len(findings) > 50:
            nodes.append(_adf_paragraph(
                f"... and {len(findings) - 50} more findings (truncated)."))
    else:
        nodes.append(_adf_paragraph("No findings."))

    return {"type": "doc", "version": 1, "content": nodes}


def build_issue_payload(meta, decision):
    e = _env()
    summary = (f"[{decision['decision']}] Skill review: "
               f"{meta.get('filename', 'bundle')}")
    return {
        "fields": {
            "project": {"key": e["project"] or "SKILL"},
            "summary": summary[:240],
            "description": _build_description(meta, decision),
            "issuetype": {"name": "Task"},
            "labels": [DECISION_LABEL.get(decision["decision"], "skillgate")],
        }
    }


def _attach_file(base_url, auth, issue_key, filename, file_bytes):
    """POST the original upload as an attachment to an existing Jira issue."""
    url = f"{base_url}/rest/api/3/issue/{issue_key}/attachments"
    boundary = "SkillGateBoundary"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: application/octet-stream\r\n"
        "\r\n"
    ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", f"Basic {auth}")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    req.add_header("X-Atlassian-Token", "no-check")  # required by Jira XSRF protection
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        resp.read()


def create_ticket(meta, decision):
    """Create a Jira issue. Returns a dict with status and key/url, or the
    dry-run payload if Jira is not configured."""
    payload = build_issue_payload(meta, decision)

    if not is_configured():
        return {"status": "dry_run", "payload": payload,
                "note": "Jira env not set; no ticket created."}

    e = _env()
    url = f"{e['base']}/rest/api/3/issue"
    body = json.dumps(payload).encode("utf-8")
    auth = base64.b64encode(f"{e['email']}:{e['token']}".encode()).decode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", f"Basic {auth}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        key = data.get("key")
        result = {"status": "created", "key": key,
                  "url": f"{e['base']}/browse/{key}" if key else None}
        upload_bytes = meta.get("upload_bytes")
        if key and upload_bytes:
            try:
                _attach_file(e["base"], auth, key,
                             meta.get("filename", "bundle"), upload_bytes)
            except Exception as ex:
                result["attachment_error"] = str(ex)[:200]
        return result
    except urllib.error.HTTPError as ex:
        detail = ex.read().decode(errors="replace")[:500]
        return {"status": "error", "code": ex.code, "detail": detail}
    except urllib.error.URLError as ex:
        return {"status": "error", "detail": str(ex.reason)}
