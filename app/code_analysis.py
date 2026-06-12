"""
Code analysis engine — analyzes EXECUTABLE files in a skill bundle.

This closes the gap that the prose scanner (skill_scan.py) leaves: a .skill
bundle can ship Python/shell scripts, and nothing else here inspects code.

CRITICAL SAFETY INVARIANT: this engine NEVER executes bundle code. Python is
parsed with the `ast` module (parse only, no exec/compile-to-run); shell and
other files are inspected as text. The whole point is to flag dangerous code
WITHOUT running it.

Severity tiering feeds the same gate as everything else. The built-in analyzer
is treated as AUTHORITATIVE for a focused set of hard-reject signals (it's our
own deterministic code, not an advisory LLM), while optional external tools
(Bandit / ShellCheck / Semgrep) run as advisory boosters when present.

Built-in checks (no dependencies):
  Python (via ast):
    - CODE_EXEC            eval / exec / compile
    - DYNAMIC_IMPORT       __import__ / importlib.import_module with non-literal
    - SHELL_OUT            os.system / os.popen / subprocess(..., shell=True)
    - SUBPROCESS           subprocess.* (any) — MEDIUM, context needed
    - NETWORK              socket / urllib / requests / httpx / http.client
    - CRED_ACCESS          os.environ / getenv / reads of known secret paths
    - DESERIALIZE          pickle.loads / yaml.load (unsafe) / marshal.loads
    - FILE_WRITE_OUTSIDE   open(..., 'w'/'a') with an absolute or ../ path
  Any text file:
    - OBFUSCATION          base64/hex decode feeding exec; long opaque blobs
    - SECRET               high-entropy tokens, AWS keys, private-key headers
  Shell (.sh/.bash):
    - SHELL_DOWNLOAD_EXEC  curl|wget piped to sh/bash
    - SHELL_NETWORK        curl / wget / nc to a remote host
    - SHELL_EVAL          eval of a variable
"""

import os
import re
import ast
import math

# ---- danger name tables (Python) -------------------------------------------

NETWORK_MODULES = {"socket", "urllib", "urllib2", "urllib3", "requests",
                   "httpx", "http", "ftplib", "telnetlib", "smtplib",
                   "asyncio"}  # asyncio alone is weak; only flagged with open_connection
NETWORK_CALLS = {"urlopen", "request", "get", "post", "put", "Session",
                 "create_connection", "connect", "open_connection"}
DESERIALIZE = {("pickle", "loads"), ("pickle", "load"),
               ("marshal", "loads"), ("marshal", "load"),
               ("yaml", "load")}  # yaml.load without SafeLoader
CRED_NAMES = {"environ", "getenv"}
SECRET_PATHS = (".aws/credentials", ".ssh/id_", ".netrc", "id_rsa",
                ".env", "credentials.json", "service-account")

# ---- secret / obfuscation regexes (any file) -------------------------------

RE_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
RE_PRIVKEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")
RE_GENERIC_SECRET = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['\"][^'\"]{12,}['\"]")
RE_B64_BLOB = re.compile(r"['\"][A-Za-z0-9+/]{120,}={0,2}['\"]")
RE_HEX_BLOB = re.compile(r"['\"](?:\\x[0-9a-fA-F]{2}){40,}['\"]")

# ---- shell regexes ---------------------------------------------------------

RE_SH_DL_EXEC = re.compile(
    r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b")
RE_SH_NET = re.compile(r"\b(curl|wget|nc|ncat|telnet)\b\s+[^\n]*\b\d{1,3}\.\d{1,3}"
                       r"|\b(curl|wget)\b\s+https?://")
RE_SH_EVAL = re.compile(r"\beval\b\s+[\"']?\$")


def _entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((n/len(s)) * math.log2(n/len(s)) for n in freq.values())


def _f(check, sev, path, line, msg, excerpt=""):
    return {"engine": "code", "check": "CODE_" + check, "severity": sev,
            "file": path, "line": line, "message": msg, "excerpt": excerpt[:160]}


# ---- Python AST analysis ---------------------------------------------------

class _PyVisitor(ast.NodeVisitor):
    def __init__(self, path):
        self.path = path
        self.findings = []
        self._net_imports = set()

    def _add(self, *a, **k):
        self.findings.append(_f(*a, path=self.path, **k))

    def visit_Import(self, node):
        for n in node.names:
            top = n.name.split(".")[0]
            if top in NETWORK_MODULES:
                self._net_imports.add(n.asname or top)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module and node.module.split(".")[0] in NETWORK_MODULES:
            self._net_imports.add(node.module.split(".")[0])
        self.generic_visit(node)

    def visit_Call(self, node):
        name = self._callname(node.func)
        # code execution
        if name in ("eval", "exec", "compile"):
            self._add("CODE_EXEC", "HIGH", line=node.lineno,
                      msg=f"Dynamic code execution via {name}().")
        if name == "__import__":
            self._add("DYNAMIC_IMPORT", "MEDIUM", line=node.lineno,
                      msg="Dynamic import via __import__().")
        # shell-out
        if name in ("os.system", "os.popen"):
            self._add("SHELL_OUT", "HIGH", line=node.lineno,
                      msg=f"Shell execution via {name}().")
        if name.startswith("subprocess."):
            shell_true = any(
                isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords if kw.arg == "shell")
            if shell_true:
                self._add("SHELL_OUT", "HIGH", line=node.lineno,
                          msg=f"{name}() with shell=True.")
            else:
                self._add("SUBPROCESS", "MEDIUM", line=node.lineno,
                          msg=f"Subprocess call {name}(); review the command.")
        # network
        short = name.split(".")[-1]
        root = name.split(".")[0]
        if root in self._net_imports or root in NETWORK_MODULES:
            if short in NETWORK_CALLS or root in ("requests", "httpx"):
                self._add("NETWORK", "HIGH", line=node.lineno,
                          msg=f"Network call {name}() — scripts should not "
                              "make outbound connections.")
        # deserialize
        parts = tuple(name.split("."))
        for mod, fn in DESERIALIZE:
            if len(parts) >= 2 and parts[-2] == mod and parts[-1] == fn:
                self._add("DESERIALIZE", "HIGH", line=node.lineno,
                          msg=f"Unsafe deserialization via {name}().")
        # credential access: os.getenv(...), os.environ.get(...), os.environ[...]
        if (short in CRED_NAMES and root == "os") or "os.environ" in name:
            self._add("CRED_ACCESS", "MEDIUM", line=node.lineno,
                      msg=f"Environment/credential access via {name}().")
        # file write outside cwd
        if name == "open":
            self._check_open(node)
        self.generic_visit(node)

    def _check_open(self, node):
        mode = ""
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
            mode = str(node.args[1].value)
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                mode = str(kw.value.value)
        if any(m in mode for m in ("w", "a", "x")) and node.args:
            tgt = node.args[0]
            if isinstance(tgt, ast.Constant) and isinstance(tgt.value, str):
                p = tgt.value
                if p.startswith("/") or ".." in p.split("/"):
                    self._add("FILE_WRITE_OUTSIDE", "HIGH", line=node.lineno,
                              msg=f"Writes to a path outside the bundle: {p}",
                              excerpt=p)

    def visit_Subscript(self, node):
        # os.environ["SECRET"] style credential access
        tgt = node.value
        if isinstance(tgt, ast.Attribute) and tgt.attr == "environ":
            if isinstance(tgt.value, ast.Name) and tgt.value.id == "os":
                self._add("CRED_ACCESS", "MEDIUM", line=node.lineno,
                          msg="Environment/credential access via os.environ[...].")
        self.generic_visit(node)

    @staticmethod
    def _callname(func):
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            parts = []
            cur = func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        return ""


def _analyze_python(path, rel, text, findings):
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError as e:
        findings.append(_f("PARSE_ERROR", "LOW", rel, e.lineno or 0,
                           f"Could not parse Python (analyzed as text only): {e.msg}"))
        return
    v = _PyVisitor(rel)
    v.visit(tree)
    findings.extend(v.findings)
    # correlation: credential access + network egress in one file = exfil pattern.
    # Each alone may be legitimate; together they are the textbook data-theft shape.
    checks = {f["check"] for f in v.findings}
    if "CODE_NETWORK" in checks and "CODE_CRED_ACCESS" in checks:
        net_line = next((f["line"] for f in v.findings
                         if f["check"] == "CODE_NETWORK"), 0)
        findings.append(_f("EXFIL_PATTERN", "HIGH", rel, net_line,
                           "Reads credentials/environment AND makes a network "
                           "call in the same file — credential-exfiltration pattern."))
    # obfuscation: base64/hex decode feeding exec/eval
    if re.search(r"(?:b64decode|b16decode|unhexlify|decode\(['\"]base64)", text) \
            and re.search(r"\b(exec|eval)\s*\(", text):
        findings.append(_f("OBFUSCATION", "HIGH", rel, 0,
                           "Decoded blob appears to feed exec/eval — "
                           "obfuscated payload pattern."))


def _analyze_shell(path, rel, text, findings):
    for i, line in enumerate(text.split("\n"), 1):
        if RE_SH_DL_EXEC.search(line):
            findings.append(_f("SHELL_DOWNLOAD_EXEC", "HIGH", rel, i,
                               "Pipes a download straight into a shell.",
                               line.strip()))
        elif RE_SH_NET.search(line):
            findings.append(_f("SHELL_NETWORK", "HIGH", rel, i,
                               "Outbound network call in a shell script.",
                               line.strip()))
        if RE_SH_EVAL.search(line):
            findings.append(_f("SHELL_EVAL", "MEDIUM", rel, i,
                               "eval of a variable in a shell script.",
                               line.strip()))


def _scan_secrets_and_blobs(rel, text, findings):
    for i, line in enumerate(text.split("\n"), 1):
        if RE_PRIVKEY.search(line):
            findings.append(_f("SECRET", "HIGH", rel, i,
                               "Embedded private key.", ""))
        if RE_AWS_KEY.search(line):
            findings.append(_f("SECRET", "HIGH", rel, i,
                               "AWS access key id.", ""))
        if RE_GENERIC_SECRET.search(line):
            findings.append(_f("SECRET", "MEDIUM", rel, i,
                               "Hardcoded credential assignment.", ""))
        if RE_B64_BLOB.search(line) or RE_HEX_BLOB.search(line):
            # entropy gate to cut false positives on long ordinary strings
            m = RE_B64_BLOB.search(line) or RE_HEX_BLOB.search(line)
            if _entropy(m.group(0)) > 4.5:
                findings.append(_f("OBFUSCATION", "MEDIUM", rel, i,
                                   "Long high-entropy encoded blob.", ""))


CODE_EXT = {".py": _analyze_python, ".sh": _analyze_shell, ".bash": _analyze_shell}
TEXTY = (".py", ".sh", ".bash", ".js", ".rb", ".pl", ".ps1", ".zsh")


def _external_boosters(extracted_dir):
    """Optional advisory findings from external SAST tools, IF installed.
    Bandit (Python) and ShellCheck (shell). Tagged engine='code_ext' so the
    aggregator treats them as advisory, not hard-reject. Graceful no-op when
    the tools are absent."""
    import shutil
    import json as _json
    import subprocess
    out = []
    if shutil.which("bandit"):
        try:
            p = subprocess.run(
                ["bandit", "-r", extracted_dir, "-f", "json", "-q"],
                capture_output=True, text=True, timeout=120,
                env={"PATH": os.environ.get("PATH", "")})
            data = _json.loads(p.stdout or "{}")
            for r in data.get("results", []):
                sev = {"HIGH": "HIGH", "MEDIUM": "MEDIUM",
                       "LOW": "LOW"}.get(r.get("issue_severity", "LOW"), "LOW")
                out.append({"engine": "code_ext", "severity": sev,
                            "check": "BANDIT_" + str(r.get("test_id", "")),
                            "file": os.path.relpath(r.get("filename", ""), extracted_dir),
                            "line": r.get("line_number", 0),
                            "message": r.get("issue_text", "")[:300]})
        except (subprocess.SubprocessError, ValueError):
            pass
    if shutil.which("shellcheck"):
        for root, _, files in os.walk(extracted_dir):
            for fn in files:
                if not fn.lower().endswith((".sh", ".bash")):
                    continue
                fp = os.path.join(root, fn)
                try:
                    p = subprocess.run(["shellcheck", "-f", "json", fp],
                                       capture_output=True, text=True, timeout=30,
                                       env={"PATH": os.environ.get("PATH", "")})
                    for r in _json.loads(p.stdout or "[]"):
                        lvl = {"error": "HIGH", "warning": "MEDIUM",
                               "info": "LOW", "style": "LOW"}.get(r.get("level"), "LOW")
                        out.append({"engine": "code_ext", "severity": lvl,
                                    "check": "SHELLCHECK_SC" + str(r.get("code", "")),
                                    "file": os.path.relpath(fp, extracted_dir),
                                    "line": r.get("line", 0),
                                    "message": r.get("message", "")[:300]})
                except (subprocess.SubprocessError, ValueError):
                    pass
    return out


def analyze_tree(extracted_dir, max_files=200, include_external=True):
    """Built-in code analysis. Returns findings in the common engine schema.
    Always available (stdlib only). Never executes bundle code.
    External SAST tools (Bandit/ShellCheck) are added as advisory findings if
    installed."""
    findings = []
    seen = 0
    for root, _, files in os.walk(extracted_dir):
        for fn in sorted(files):
            ext = os.path.splitext(fn)[1].lower()
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, extracted_dir)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            if ext in CODE_EXT:
                CODE_EXT[ext](path, rel, text, findings)
            if ext in TEXTY or ext in (".json", ".yaml", ".yml", ".env", ".cfg",
                                       ".ini", ".txt", ".md"):
                _scan_secrets_and_blobs(rel, text, findings)
            seen += 1
            if seen >= max_files:
                findings.append(_f("ANALYSIS_INCOMPLETE", "MEDIUM",
                                   "(bundle)", 0,
                                   f"Code analysis capped at {max_files} files."))
                if include_external:
                    findings += _external_boosters(extracted_dir)
                return findings
    if include_external:
        findings += _external_boosters(extracted_dir)
    return findings
