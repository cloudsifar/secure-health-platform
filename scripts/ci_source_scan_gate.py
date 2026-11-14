#!/usr/bin/env python3
"""
Gate 1 (part 2): Code and Dockerfile policy scan - cp-secure-health-platform v2

Runs BEFORE the Docker build, after gitleaks has scanned the tree for
credentials. Responsibilities are split deliberately:

  gitleaks (buildspec, Gate 1 part 1)  -> credential detection, every file
  this script                          -> project-specific policy:
    1. Dangerous Python calls, found by parsing the code (ast), with import
       aliases resolved (import subprocess as sp, from os import system)
    2. Dockerfile policy, using a parser that handles line continuations,
       quoting, multi-assignment ENV/ARG and the # escape= directive:
         DOCKERFILE_SECRET_ARG / _ENV  secret-like names passed through ARG/ENV
                                       (build args persist in image history,
                                       ENV persists in the image config)
         DOCKERFILE_UNPINNED_BASE      FROM with no tag, or :latest
         DOCKERFILE_RUNS_AS_ROOT       final stage has no non-root USER

Suppressions must name the rule and give a reason; they are logged:
  Python:      x = eval(s)  # source-scan: allow DANGEROUS_CALL:eval reason="..."
               (same line, or a comment on the line directly above)
  Dockerfile:  # source-scan: allow DOCKERFILE_SECRET_ENV reason="..."
               (a comment line directly above the instruction)

Fail-closed: any unsuppressed finding, any unparseable Python file, or any
unexpected error exits non-zero. Exit codes: 0 pass, 1 findings, 2 error.
"""
import ast
import logging
import os
import re
import shlex
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s", stream=sys.stdout)
log = logging.getLogger("source-scan")

REPO_ROOT = os.environ.get("CODEBUILD_SRC_DIR") or os.getcwd()
MAX_FILE_BYTES = int(os.environ.get("SCAN_MAX_FILE_BYTES", "512000"))

EXCLUDED_DIRS = {
    ".git", ".github", ".pytest_cache", ".terraform", ".venv", "venv",
    "__pycache__", "build", "dist", "node_modules",
}

SUPPRESS_RE = re.compile(r"#\s*source-scan:\s*allow\s+(\S+)\s+reason=\"([^\"]+)\"")
SUPPRESS_MALFORMED_RE = re.compile(r"#\s*source-scan:\s*allow\b")

# --- Python ------------------------------------------------------------------
DANGEROUS_CALLS = {
    "eval", "exec", "os.system", "os.popen",
    "pickle.load", "pickle.loads", "marshal.load", "marshal.loads",
}

# --- Dockerfile --------------------------------------------------------------
SECRET_NAME_RE = re.compile(
    r"(?i)(SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL)"
)
# Names that point AT a secret rather than holding one (e.g. a mounted file).
# _ID is deliberately absent so AWS_ACCESS_KEY_ID is still caught.
REFERENCE_SUFFIX_RE = re.compile(r"(?i)_(PATH|FILE|DIR|URL|URI|ARN|ENDPOINT|NAME)$")
ROOT_USERS = {"root", "0", "0:0", "root:root"}

DOCKERFILE_REMEDIATION = (
    "Do not pass secrets through ARG/ENV: use BuildKit secret mounts "
    "(RUN --mount=type=secret) at build time, or ECS task-definition 'secrets' "
    "(Secrets Manager/SSM) at runtime."
)


class Finding:
    __slots__ = ("rule", "rel", "line", "detail")

    def __init__(self, rule, rel, line, detail=""):
        self.rule, self.rel, self.line, self.detail = rule, rel, line, detail


# ============================================================================
# File walking
# ============================================================================
def iter_files(root):
    """os.walk the repo, pruning excluded dirs in place so they are never entered."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            if not os.path.islink(path):
                yield path, os.path.relpath(path, root), name


def read_bytes(path):
    """Return file bytes, or None if too large or binary."""
    if os.path.getsize(path) > MAX_FILE_BYTES:
        return None
    with open(path, "rb") as fh:
        data = fh.read()
    if b"\x00" in data[:8192]:
        return None
    return data


def is_dockerfile(name):
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile")


# ============================================================================
# Suppressions
# ============================================================================
def parse_suppression(text):
    """Return (rule, reason) for a well-formed suppression, 'malformed', or None."""
    m = SUPPRESS_RE.search(text)
    if m:
        return m.group(1), m.group(2).strip()
    if SUPPRESS_MALFORMED_RE.search(text):
        return "malformed"
    return None


# ============================================================================
# Python: dangerous calls via AST, with import aliases resolved
# ============================================================================
def build_alias_map(tree):
    """Map local names to canonical dotted names from import statements."""
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for a in node.names:
                aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    return aliases


def resolve_call(node, aliases):
    func = node.func
    if isinstance(func, ast.Name):
        return aliases.get(func.id, func.id)
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        base = aliases.get(func.value.id, func.value.id)
        return f"{base}.{func.attr}"
    return None


def scan_python(data, rel):
    try:
        tree = ast.parse(data, filename=rel)
    except (SyntaxError, ValueError) as exc:
        return [Finding("UNPARSEABLE_PYTHON", rel, getattr(exc, "lineno", 0) or 0)]

    aliases = build_alias_map(tree)
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = resolve_call(node, aliases)
        if not name:
            continue
        if name in DANGEROUS_CALLS:
            findings.append(Finding(f"DANGEROUS_CALL:{name}", rel, node.lineno))
        elif name.startswith("subprocess.") and any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        ):
            findings.append(Finding("SUBPROCESS_SHELL_TRUE", rel, node.lineno, name))
        elif name == "yaml.load" and not any(kw.arg == "Loader" for kw in node.keywords):
            findings.append(Finding("YAML_UNSAFE_LOAD", rel, node.lineno))
    return findings


def python_suppression(lines, lineno):
    """Suppression on the finding's line, or a comment-only line directly above."""
    candidates = []
    if 1 <= lineno <= len(lines):
        candidates.append(lines[lineno - 1])
    if 2 <= lineno <= len(lines) + 1 and lines[lineno - 2].lstrip().startswith("#"):
        candidates.append(lines[lineno - 2])
    for text in candidates:
        s = parse_suppression(text)
        if s:
            return s
    return None


# ============================================================================
# Dockerfile: logical-instruction parser + policy
# ============================================================================
def parse_dockerfile(text):
    """
    Yield (instruction, args, start_line, suppression) for each logical instruction.
    Handles the '# escape=' parser directive, line continuations, comment lines
    (including comments inside a continuation), and blank lines.
    """
    lines = text.splitlines()
    escape = "\\"
    # Parser directives must appear before any instruction, blank line or comment.
    for raw in lines:
        m = re.match(r"^\s*#\s*escape\s*=\s*([\\`])\s*$", raw, re.I)
        if m:
            escape = m.group(1)
            continue
        if re.match(r"^\s*#\s*\w+\s*=", raw):
            continue
        break

    pending_suppression = None
    buf, start = [], None
    for idx, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not buf:
            if not stripped:
                pending_suppression = None
                continue
            if stripped.startswith("#"):
                s = parse_suppression(stripped)
                if s:
                    pending_suppression = s
                continue
            start = idx
        elif stripped.startswith("#") or not stripped:
            continue  # comments/blank lines inside a continuation are dropped
        if stripped.endswith(escape):
            buf.append(stripped[:-1])
            continue
        buf.append(stripped)
        logical = " ".join(part.strip() for part in buf)
        buf = []
        parts = logical.split(None, 1)
        yield parts[0].upper(), (parts[1] if len(parts) > 1 else ""), start, pending_suppression
        pending_suppression = None
    if buf:
        logical = " ".join(part.strip() for part in buf)
        parts = logical.split(None, 1)
        yield parts[0].upper(), (parts[1] if len(parts) > 1 else ""), start, pending_suppression


def split_args(args):
    """Tokenise like a shell (quotes respected); fall back to whitespace on bad quoting."""
    try:
        return shlex.split(args, posix=True)
    except ValueError:
        return args.split()


def declared_names(instruction, args):
    """Variable names declared by an ENV or ARG instruction."""
    tokens = split_args(args)
    if not tokens:
        return []
    if instruction == "ENV" and "=" not in tokens[0]:
        return [tokens[0]]  # legacy form: ENV NAME value with spaces
    return [t.split("=", 1)[0] for t in tokens if t and not t.startswith("-")]


def is_secret_name(name):
    return bool(SECRET_NAME_RE.search(name)) and not REFERENCE_SUFFIX_RE.search(name)


def parse_from(args):
    """Return (image_ref, stage_alias) from a FROM instruction's arguments."""
    tokens = [t for t in split_args(args) if not t.startswith("--")]
    if not tokens:
        return None, None
    image = tokens[0]
    alias = tokens[2] if len(tokens) >= 3 and tokens[1].upper() == "AS" else None
    return image, alias


def base_is_unpinned(image, stage_names):
    if image.lower() == "scratch" or image in stage_names or "$" in image:
        return False
    if "@sha256:" in image:
        return False
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return True
    return last.rsplit(":", 1)[1].lower() == "latest"


def scan_dockerfile(text, rel):
    """Return list of (Finding, suppression)."""
    results = []
    stage_names = set()
    final_stage_user = None  # last USER seen in the current (final) stage
    final_stage_line = None
    final_stage_suppression = None

    for instruction, args, line, suppression in parse_dockerfile(text):
        if instruction == "FROM":
            image, alias = parse_from(args)
            final_stage_user, final_stage_line, final_stage_suppression = None, line, suppression
            if image and base_is_unpinned(image, stage_names):
                results.append((Finding("DOCKERFILE_UNPINNED_BASE", rel, line, image), suppression))
            if alias:
                stage_names.add(alias)
        elif instruction in ("ENV", "ARG"):
            for name in declared_names(instruction, args):
                if is_secret_name(name):
                    results.append((Finding(f"DOCKERFILE_SECRET_{instruction}", rel, line, name), suppression))
        elif instruction == "USER":
            tokens = split_args(args)
            final_stage_user = tokens[0] if tokens else None

    if final_stage_line is not None and (final_stage_user is None or final_stage_user.lower() in ROOT_USERS):
        detail = "no USER instruction" if final_stage_user is None else f"USER {final_stage_user}"
        # Reported against the final FROM line; suppress with a comment directly above it.
        results.append((Finding("DOCKERFILE_RUNS_AS_ROOT", rel, final_stage_line, detail),
                        final_stage_suppression))
    return results


# ============================================================================
# Main
# ============================================================================
def apply_suppression(finding, suppression, suppressed, findings, warnings):
    if suppression == "malformed":
        warnings.append(f"Malformed suppression at {finding.rel}:{finding.line} ignored "
                        '(format: # source-scan: allow <RULE> reason="...")')
        findings.append(finding)
    elif suppression and suppression[0] == finding.rule:
        suppressed.append((finding, suppression[1]))
    else:
        findings.append(finding)


def main():
    log.info("Gate 1: Code and Dockerfile policy scan starting")
    log.info(f"Repo root: {REPO_ROOT}")
    log.info(f"Max file size: {MAX_FILE_BYTES} bytes")
    log.info(f"Excluded dirs: {', '.join(sorted(EXCLUDED_DIRS))}")
    log.info("Checks: dangerous Python calls (AST, aliases resolved); Dockerfile ARG/ENV secret names, "
             "unpinned base images, root user")

    if not os.path.isdir(REPO_ROOT):
        log.error(f"FAIL: Repo root does not exist: {REPO_ROOT}")
        return 2

    findings, suppressed, warnings = [], [], []
    py_count = df_count = 0

    for path, rel, name in iter_files(REPO_ROOT):
        if not (name.endswith(".py") or is_dockerfile(name)):
            continue
        data = read_bytes(path)
        if data is None:
            continue
        text = data.decode("utf-8", errors="replace")

        if name.endswith(".py"):
            py_count += 1
            lines = text.splitlines()
            for f in scan_python(data, rel):
                sup = None if f.rule == "UNPARSEABLE_PYTHON" else python_suppression(lines, f.line)
                apply_suppression(f, sup, suppressed, findings, warnings)
        if is_dockerfile(name):
            df_count += 1
            for f, sup in scan_dockerfile(text, rel):
                apply_suppression(f, sup, suppressed, findings, warnings)

    log.info(f"Files scanned: {py_count} Python, {df_count} Dockerfile")

    for f, reason in sorted(suppressed, key=lambda x: (x[0].rel, x[0].line)):
        detail = f" {f.detail}" if f.detail else ""
        log.warning(f"SUPPRESSED [{f.rule}] {f.rel}:{f.line}{detail} reason=\"{reason}\"")
    for w in warnings:
        log.warning(w)

    if findings:
        for f in sorted(findings, key=lambda x: (x.rel, x.line)):
            detail = f" ({f.detail})" if f.detail else ""
            log.error(f"FINDING [{f.rule}] {f.rel}:{f.line}{detail}")
        if any(f.rule.startswith("DOCKERFILE_SECRET_") for f in findings):
            log.error(f"REMEDIATION: {DOCKERFILE_REMEDIATION}")
        log.error(f"FAIL: Code/Dockerfile policy scan triggered ({len(findings)} finding(s)).")
        return 1

    log.info(f"PASS: Code/Dockerfile policy satisfied (0 finding(s), {len(suppressed)} suppressed).")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # fail closed on anything unexpected
        log.error(f"FAIL: Policy scan error ({type(exc).__name__}: {exc}) - blocking deployment")
        sys.exit(2)
