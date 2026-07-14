#!/usr/bin/env python3
"""Simple static vulnerability scanner for source code repositories."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    severity: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    severity: str
    rule_id: str
    message: str
    snippet: str


RULES: tuple[Rule, ...] = (
    Rule(
        id="SECRET_AWS_KEY",
        description="Possible hardcoded AWS access key",
        severity="high",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
    Rule(
        id="SECRET_PRIVATE_KEY",
        description="Possible private key material committed",
        severity="critical",
        pattern=re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) PRIVATE KEY-----"),
    ),
    Rule(
        id="SECRET_PASSWORD_LITERAL",
        description="Possible hardcoded password",
        severity="medium",
        pattern=re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]"),
    ),
    Rule(
        id="PYTHON_EVAL",
        description="Use of eval() may allow code injection",
        severity="high",
        pattern=re.compile(r"\beval\s*\("),
    ),
    Rule(
        id="PYTHON_EXEC",
        description="Use of exec() may allow code injection",
        severity="high",
        pattern=re.compile(r"\bexec\s*\("),
    ),
    Rule(
        id="COMMAND_SHELL_TRUE",
        description="subprocess with shell=True can enable command injection",
        severity="high",
        pattern=re.compile(r"\bsubprocess\.(run|Popen|call|check_output|check_call)\s*\(.*shell\s*=\s*True"),
    ),
    Rule(
        id="OS_SYSTEM_CALL",
        description="os.system() can enable command injection",
        severity="medium",
        pattern=re.compile(r"\bos\.system\s*\("),
    ),
    Rule(
        id="PICKLE_LOADS",
        description="pickle.loads on untrusted input can lead to code execution",
        severity="high",
        pattern=re.compile(r"\bpickle\.loads\s*\("),
    ),
)

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", ".pytest_cache"}
SCAN_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".rs",
    ".sh",
    ".yml",
    ".yaml",
    ".json",
    ".env",
    ".ini",
    ".toml",
}


def should_scan_file(path: Path, max_file_size: int) -> bool:
    if not path.is_file():
        return False
    if path.stat().st_size > max_file_size:
        return False
    if path.suffix.lower() in SCAN_SUFFIXES:
        return True
    return path.name.lower() in {"dockerfile", ".env"}


def iter_files(target: Path, max_file_size: int) -> Iterator[Path]:
    if target.is_file():
        if should_scan_file(target, max_file_size):
            yield target
        return

    for path in target.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if should_scan_file(path, max_file_size):
            yield path


def scan_lines(file_path: Path, min_severity: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for number, line in enumerate(handle, start=1):
                for rule in RULES:
                    if SEVERITY_ORDER[rule.severity] < SEVERITY_ORDER[min_severity]:
                        continue
                    if rule.pattern.search(line):
                        findings.append(
                            Finding(
                                file=str(file_path),
                                line=number,
                                severity=rule.severity,
                                rule_id=rule.id,
                                message=rule.description,
                                snippet=line.strip()[:240],
                            )
                        )
    except OSError:
        return findings

    return findings


def summarize(findings: Iterable[Finding]) -> dict[str, int]:
    summary = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for finding in findings:
        summary[finding.severity] += 1
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lightweight vulnerability scanner")
    parser.add_argument("target", nargs="?", default=".", help="File or directory to scan")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--min-severity",
        choices=tuple(SEVERITY_ORDER),
        default="low",
        help="Only include findings at or above this severity",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(SEVERITY_ORDER),
        default="high",
        help="Exit with code 1 if findings at or above this severity exist",
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=1024 * 1024,
        help="Max file size in bytes to scan",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target = Path(args.target).resolve()

    if not target.exists():
        print(f"Target does not exist: {target}", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    for file_path in iter_files(target, args.max_file_size):
        findings.extend(scan_lines(file_path, args.min_severity))

    findings.sort(key=lambda item: (item.file, item.line, -SEVERITY_ORDER[item.severity]))
    summary = summarize(findings)

    if args.format == "json":
        print(
            json.dumps(
                {
                    "target": str(target),
                    "total_findings": len(findings),
                    "summary": summary,
                    "findings": [asdict(item) for item in findings],
                },
                indent=2,
            )
        )
    else:
        print(f"Scan target: {target}")
        print(f"Total findings: {len(findings)}")
        print(
            "Summary: "
            + ", ".join(f"{name}={count}" for name, count in summary.items() if count)
            if len(findings)
            else "Summary: no findings"
        )
        for finding in findings:
            print(
                f"[{finding.severity.upper()}] {finding.rule_id} "
                f"{finding.file}:{finding.line} - {finding.message}"
            )

    fail_threshold = SEVERITY_ORDER[args.fail_on]
    should_fail = any(SEVERITY_ORDER[item.severity] >= fail_threshold for item in findings)
    return 1 if should_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
