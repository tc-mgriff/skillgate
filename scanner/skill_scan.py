#!/usr/bin/env python3
"""
skill_scan.py — static review checks for Claude skill bundles before org import.

Scans an extracted skill tree (a directory containing SKILL.md and optional
references/, scripts/, etc.) and reports findings. Designed to run in CI and
exit non-zero on any HIGH finding so a merge is blocked pending human sign-off.

Two primary checks motivated by the threat model:
  1. CROSS_FILE_AUTHORITY — SKILL.md instructs the model to read a separate
     file AND treat its contents as authoritative / overriding. This is the
     control-flow-points-at-payload split where injection hides in a reference
     file the human reviewer skims.
  2. BROAD_DESCRIPTION — frontmatter `description` claims broad or proactive
     invocation, or contains imperative override language. An invocation-hygiene
     issue: the skill fires in contexts the user didn't intend and pulls its
     instructions + referenced payloads into context unbidden.

Plus supporting hygiene checks (frontmatter shape, hidden chars, egress URLs).

Usage:
    python skill_scan.py <path-to-extracted-skill-dir>
    python skill_scan.py <path-to-single-SKILL.md>

Exit codes: 0 = no HIGH findings, 1 = at least one HIGH finding, 2 = usage error.
"""

import os
import re
import sys
import json
import unicodedata

# --- severity ---------------------------------------------------------------

HIGH, MED, LOW = "HIGH", "MEDIUM", "LOW"

# --- patterns ---------------------------------------------------------------

# A "read this other file" instruction: an imperative read verb pointing at a
# path-like token (something with a slash or a .md/.txt/.json extension).
READ_VERB = re.compile(
    r"\b(read|open|load|consult|review|follow|ingest|see|refer to|fetch)\b",
    re.IGNORECASE,
)
PATHLIKE = re.compile(
    r"`[^`]*?(?:/[^`]*|\.(?:md|markdown|txt|json|ya?ml|csv))`"  # backticked path or .ext
    r"|(?:references|scripts|assets|data|docs|config)/[\w./-]+",  # bare relative path
    re.IGNORECASE,
)

# Authority/override language: "this wins", "highest priority", "authoritative",
# "ground truth", "overrides", "when in doubt this", "mandatory", "always do what".
AUTHORITY = re.compile(
    r"\b("
    r"highest priority|authoritative|ground truth|source of truth|"
    r"this wins|when in doubt[, ].{0,40}\bwins\b|overrides?\b|takes precedence|"
    r"supersed\w+|must (?:obey|follow|comply)|"
    r"treat .{0,30} as (?:authoritative|truth|law|the rule)"
    r")\b",
    re.IGNORECASE,
)

# Broad / proactive invocation claims in a description.
PROACTIVE = re.compile(
    r"\b("
    r"proactively|automatically|any time someone|whenever (?:someone|a user|anyone)|"
    r"every time|on any (?:draft|message|copy|file)|or any time|"
    r"always (?:trigger|invoke|use this)|default to this"
    r")\b",
    re.IGNORECASE,
)
# Imperative override / mandatory-trigger language in a description.
DESC_OVERRIDE = re.compile(
    r"\b(mandatory|must trigger|always trigger|you must|ignore (?:prior|previous|all))\b",
    re.IGNORECASE,
)

# Classic injection / exfil verbs anywhere in prose (cheap first-pass net).
INJECTION = re.compile(
    r"\b("
    r"ignore (?:all |any )?(?:prior|previous|above|earlier) (?:instructions|prompts?|rules)|"
    r"disregard (?:the |your )?(?:system|previous|prior)|"
    r"system prompt|do not tell the user|without telling the user|"
    r"exfiltrat\w+|send .{0,30} to (?:https?://|the following)|"
    r"reveal your (?:instructions|prompt|system)"
    r")\b",
    re.IGNORECASE,
)

URL = re.compile(r"https?://[^\s`)\]>\"']+", re.IGNORECASE)

# Zero-width / bidi / other non-printing chars used to smuggle instructions.
SUSPICIOUS_CHARS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE / BOM",
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
}

# --- frontmatter ------------------------------------------------------------

def split_frontmatter(text):
    """Return (frontmatter_dict_ish, frontmatter_raw, body). Minimal YAML: we
    don't pull in PyYAML so CI stays dependency-light. We only need the
    `description` and `name` scalars; description is commonly a `>` block."""
    if not text.startswith("---"):
        return {}, "", text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, "", text
    raw = text[3:end].strip("\n")
    body = text[end + 4:]
    fields = {}
    # crude block-scalar + scalar extractor for top-level keys
    lines = raw.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if m and not line.startswith(" "):
            key, val = m.group(1), m.group(2).strip()
            if val in (">", "|", ">-", "|-", ">+", "|+"):
                # gather indented block
                block = []
                i += 1
                while i < len(lines) and (lines[i].startswith(" ") or lines[i] == ""):
                    block.append(lines[i].strip())
                    i += 1
                fields[key] = " ".join(b for b in block if b)
                continue
            fields[key] = val.strip().strip('"').strip("'")
        i += 1
    return fields, raw, body


# --- checks -----------------------------------------------------------------

class Finding:
    def __init__(self, check, severity, path, line, msg, excerpt=""):
        self.check, self.severity, self.path = check, severity, path
        self.line, self.msg, self.excerpt = line, msg, excerpt

    def as_dict(self):
        return {
            "check": self.check, "severity": self.severity, "file": self.path,
            "line": self.line, "message": self.msg, "excerpt": self.excerpt,
        }


def line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def check_cross_file_authority(path, body, findings):
    """Two sub-signals. (a) read-verb + pathlike on the same line = a reference
    pull; informational on its own. (b) the SAME paragraph/line also carries
    authority language = the file is told to treat an external file as
    overriding. (b) is the HIGH finding."""
    for ln_no, line in enumerate(body.split("\n"), 1):
        has_path = PATHLIKE.search(line)
        if not has_path:
            continue
        has_read = READ_VERB.search(line)
        has_auth = AUTHORITY.search(line)
        if has_read and has_auth:
            findings.append(Finding(
                "CROSS_FILE_AUTHORITY", HIGH, path, ln_no,
                "Instructs the model to read an external file AND treat it as "
                "authoritative/overriding on the same line. Payload can be staged "
                "in the referenced file to evade SKILL.md review.",
                line.strip()[:200]))
        elif has_auth and has_path:
            findings.append(Finding(
                "CROSS_FILE_AUTHORITY", MED, path, ln_no,
                "External file reference elevated with authority language "
                "(no explicit read verb on this line; check surrounding context).",
                line.strip()[:200]))
        elif has_read and has_path:
            findings.append(Finding(
                "CROSS_FILE_AUTHORITY", LOW, path, ln_no,
                "Reference pull (read-verb + path). Expected in legitimate skills; "
                "confirm the referenced file is in-bundle and reviewed.",
                line.strip()[:200]))


def check_description(path, fields, raw, findings):
    desc = fields.get("description", "")
    if not desc:
        findings.append(Finding(
            "BROAD_DESCRIPTION", LOW, path, 1,
            "No description field found in frontmatter.", ""))
        return
    # rough length signal
    words = len(desc.split())
    if words > 120:
        findings.append(Finding(
            "BROAD_DESCRIPTION", MED, path, 1,
            f"Description is very long ({words} words). Long trigger surfaces "
            "tend to over-claim invocation scope; review for scope creep.",
            desc[:160] + ("..." if len(desc) > 160 else "")))
    if PROACTIVE.search(desc):
        findings.append(Finding(
            "BROAD_DESCRIPTION", HIGH, path, 1,
            "Description claims proactive/automatic invocation. Skill may fire "
            "unbidden and pull its instructions + referenced files into context "
            "without the user explicitly invoking it.",
            _hit(PROACTIVE, desc)))
    if DESC_OVERRIDE.search(desc):
        findings.append(Finding(
            "BROAD_DESCRIPTION", HIGH, path, 1,
            "Description contains mandatory/override trigger language "
            "('mandatory', 'must trigger', etc.). Forces invocation against "
            "the model's own judgment.",
            _hit(DESC_OVERRIDE, desc)))
    # count distinct quoted trigger phrases — many = broad surface
    quoted = re.findall(r'"([^"]{3,60})"', desc)
    if len(quoted) >= 6:
        findings.append(Finding(
            "BROAD_DESCRIPTION", MED, path, 1,
            f"Description enumerates {len(quoted)} quoted trigger phrases. "
            "Broad trigger surface; check for overlap with other org skills "
            "(invocation collisions).", "; ".join(quoted[:6]) + " ..."))


def check_injection(path, text, findings):
    for m in INJECTION.finditer(text):
        findings.append(Finding(
            "INJECTION_PATTERN", HIGH, path, line_of(text, m.start()),
            "Instruction-override / exfiltration phrasing detected.",
            text[max(0, m.start()-30):m.end()+30].replace("\n", " ").strip()))


def check_hidden_chars(path, text, findings):
    for ch, name in SUSPICIOUS_CHARS.items():
        idx = text.find(ch)
        if idx != -1:
            findings.append(Finding(
                "HIDDEN_CHARS", HIGH, path, line_of(text, idx),
                f"Non-printing character present: {name} (U+{ord(ch):04X}). "
                "Can smuggle instructions invisible to a human reviewer.", ""))


def check_egress(path, text, findings):
    seen = set()
    for m in URL.finditer(text):
        u = m.group(0).rstrip(".,);")
        if u in seen:
            continue
        seen.add(u)
        findings.append(Finding(
            "EGRESS_URL", LOW, path, line_of(text, m.start()),
            "External URL referenced. Add to egress inventory; confirm against "
            "allowlist.", u))


def _hit(pat, s):
    m = pat.search(s)
    if not m:
        return ""
    return s[max(0, m.start()-20):m.end()+40].strip()


# --- archive (zip) pre-extraction safety, optional --------------------------

def check_zip(zip_path, findings):
    import zipfile
    try:
        zf = zipfile.ZipFile(zip_path)
    except Exception as e:
        findings.append(Finding("ARCHIVE", HIGH, zip_path, 0,
                                f"Could not open archive: {e}", ""))
        return
    total_unc = 0
    total_comp = 0
    for info in zf.infolist():
        name = info.filename
        total_unc += info.file_size
        total_comp += info.compress_size
        if name.startswith("/") or ".." in name.replace("\\", "/").split("/"):
            findings.append(Finding("ARCHIVE", HIGH, zip_path, 0,
                f"Path traversal / absolute path in entry: {name}", name))
        # symlink detection: external_attr high bits encode unix mode
        mode = info.external_attr >> 16
        if mode and (mode & 0o170000) == 0o120000:
            findings.append(Finding("ARCHIVE", HIGH, zip_path, 0,
                f"Symlink entry in archive: {name}", name))
    if total_comp > 0 and total_unc / max(total_comp, 1) > 100:
        findings.append(Finding("ARCHIVE", HIGH, zip_path, 0,
            f"High decompression ratio {total_unc/total_comp:.0f}x "
            "(possible zip bomb).", ""))


# --- driver -----------------------------------------------------------------

def scan_text_file(path, findings, is_skill_md=False):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    fields, raw, body = split_frontmatter(text)
    if is_skill_md:
        check_description(path, fields, raw, findings)
        check_cross_file_authority(path, body, findings)
    else:
        # reference files: still scan the whole thing for cross-file/auth + injection
        check_cross_file_authority(path, text, findings)
    check_injection(path, text, findings)
    check_hidden_chars(path, text, findings)
    check_egress(path, text, findings)


def main(argv):
    if len(argv) != 2:
        print("usage: skill_scan.py <skill-dir-or-SKILL.md-or-.skill-zip>", file=sys.stderr)
        return 2
    target = argv[1]
    findings = []

    if target.endswith((".skill", ".zip")):
        check_zip(target, findings)
        # NOTE: extraction + recursive scan would happen in sandbox; omitted here.
    elif os.path.isdir(target):
        for root, _, files in os.walk(target):
            for fn in files:
                p = os.path.join(root, fn)
                if fn.lower().endswith((".md", ".markdown", ".txt")):
                    scan_text_file(p, findings, is_skill_md=(fn == "SKILL.md"))
    elif os.path.isfile(target):
        scan_text_file(target, findings, is_skill_md=os.path.basename(target) == "SKILL.md")
    else:
        print(f"not found: {target}", file=sys.stderr)
        return 2

    order = {HIGH: 0, MED: 1, LOW: 2}
    findings.sort(key=lambda f: (order[f.severity], f.check, f.line))

    report = {
        "target": target,
        "summary": {s: sum(1 for f in findings if f.severity == s) for s in (HIGH, MED, LOW)},
        "findings": [f.as_dict() for f in findings],
    }
    print(json.dumps(report, indent=2))
    return 1 if report["summary"][HIGH] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
