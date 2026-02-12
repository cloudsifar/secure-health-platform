#!/usr/bin/env python3
"""
Gate 4: Secrets Detection

Scans the checked-out repository for accidentally committed credentials/secrets.
Fails the build if any findings are detected.

Design goals:
- Fast, deterministic, CI-friendly output
- Low false positives by default (tunable)
- Clear logs for screenshots + incident-style triage
"""

from __future__ import annotations

import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Tuple

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("secrets-gate")


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern
    severity: str  # INFO/WARN/CRITICAL


def _compile_rules() -> List[Rule]:
    # Keep these practical and "obviously bad" for v1.
    # You can tune/expand later.
    return [
        Rule(
            "AWS_ACCESS_KEY_ID",
            re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
            "CRITICAL",
        ),
        Rule(
            "AWS_SECRET_ACCESS_KEY_ASSIGNMENT",
            re.compile(
                r"(?i)\baws_secret_access_key\b\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"
            ),
            "CRITICAL",
        ),
        Rule(
            "AWS_SESSION_TOKEN_ASSIGNMENT",
            re.compile(
                r"(?i)\baws_session_token\b\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{80,}['\"]?"
            ),
            "CRITICAL",
        ),
        Rule(
            "PRIVATE_KEY_BLOCK",
            re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"),
            "CRITICAL",
        ),
        Rule(
            "GITHUB_TOKEN",
            re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
            "CRITICAL",
        ),
        Rule(
            "SLACK_TOKEN",
            re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
            "CRITICAL",
        ),
        Rule(
            "JWT_LIKE",
            re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]{10,}\.[a-zA-Z0-9._-]{10,}\b"),
            "WARN",
        ),
        Rule(
            "PASSWORD_ASSIGNMENT",
            re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
            "WARN",
        ),
        Rule(
            "CONNECTION_STRING",
            re.compile(r"(?i)\b(postgres|mysql|mongodb|redis)://[^ \n]+"),
            "WARN",
        ),
    ]


EXCLUDE_DIRS_DEFAULT = {
    ".git",
    ".github",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    ".terraform",
    ".pytest_cache",
}

EXCLUDE_FILES_DEFAULT = {
    # Add any known safe/noisy files here if needed later
}

# File extensions we generally don't want to scan (binary-ish / huge noise).
SKIP_EXT_DEFAULT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".pdf",
    ".zip", ".tar", ".gz", ".bz2", ".7z",
    ".exe", ".dll", ".so", ".dylib",
    ".jar",
}

MAX_FILE_BYTES_DEFAULT = 512_000  # 512 KB


def _is_probably_binary(data: bytes) -> bool:
    # Simple heuristic: NUL byte = likely binary
    return b"\x00" in data


def _mask_match(s: str) -> str:
    # Mask long values so logs are safe to screenshot.
    if len(s) <= 12:
        return "***"
    return s[:4] + "…" + s[-4:]


def _env_csv(name: str) -> List[str]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def _should_exclude_path(path: Path, repo_root: Path, exclude_dirs: set[str]) -> bool:
    rel = path.relative_to(repo_root)
    for part in rel.parts:
        if part in exclude_dirs:
            return True
    return False


def _iter_files(repo_root: Path, exclude_dirs: set[str]) -> Iterable[Path]:
    for p in repo_root.rglob("*"):
        if p.is_dir():
            continue
        if _should_exclude_path(p, repo_root, exclude_dirs):
            continue
        yield p


def _scan_file(path: Path, rules: List[Rule], max_bytes: int) -> List[Tuple[Rule, int, str]]:
    findings: List[Tuple[Rule, int, str]] = []

    try:
        size = path.stat().st_size
        if size > max_bytes:
            return findings

        data = path.read_bytes()
        if _is_probably_binary(data):
            return findings

        text = data.decode("utf-8", errors="replace")
    except Exception as e:
        log.warning("Could not read %s (%s) — skipping", path.as_posix(), e)
        return findings

    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        # quick skip for obviously empty lines
        if not line.strip():
            continue

        for rule in rules:
            m = rule.pattern.search(line)
            if m:
                snippet = _mask_match(m.group(0))
                findings.append((rule, idx, snippet))

    return findings


def main() -> int:
    repo_root = Path(os.environ.get("CODEBUILD_SRC_DIR", ".")).resolve()

    exclude_dirs = set(EXCLUDE_DIRS_DEFAULT)
    exclude_dirs.update(_env_csv("SECRETS_EXCLUDE_DIRS"))

    exclude_files = set(EXCLUDE_FILES_DEFAULT)
    exclude_files.update(_env_csv("SECRETS_EXCLUDE_FILES"))

    skip_ext = set(SKIP_EXT_DEFAULT)
    skip_ext.update(_env_csv("SECRETS_SKIP_EXT"))

    max_bytes = int(os.environ.get("SECRETS_MAX_FILE_BYTES", str(MAX_FILE_BYTES_DEFAULT)))

    rules = _compile_rules()

    log.info("Gate 4: Secrets detection starting")
    log.info("Repo root: %s", repo_root.as_posix())
    log.info("Max file size: %d bytes", max_bytes)
    if exclude_dirs:
        log.info("Excluded dirs: %s", ", ".join(sorted(exclude_dirs)))

    total = 0

    for f in _iter_files(repo_root, exclude_dirs):
        if f.name in exclude_files:
            continue
        if f.suffix.lower() in skip_ext:
            continue

        hits = _scan_file(f, rules, max_bytes)
        if hits:
            rel = f.relative_to(repo_root).as_posix()
            for rule, line_no, masked in hits:
                total += 1
                level = rule.severity.upper()
                # Use logging severity for readability in CodeBuild
                if level == "CRITICAL":
                    log.error("FINDING [%s] %s:%d match=%s", rule.name, rel, line_no, masked)
                else:
                    log.warning("FINDING [%s] %s:%d match=%s", rule.name, rel, line_no, masked)

    if total:
        log.error("❌ FAIL: Secrets gate triggered (%d finding(s)). Remove secrets and rotate any exposed creds.", total)
        return 1

    log.info("✅ PASS: Secrets gate satisfied (no findings).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
