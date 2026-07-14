import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Finding:
    file_path: str
    line_number: int
    severity: str
    message: str
    pattern: str


RULES = (
    (re.compile(r"\beval\s*\("), "HIGH", "Use of eval can lead to code injection."),
    (re.compile(r"\bexec\s*\("), "HIGH", "Use of exec can lead to code injection."),
    (
        re.compile(r"subprocess\.(run|Popen)\(.*shell\s*=\s*True"),
        "HIGH",
        "subprocess call with shell=True can be unsafe.",
    ),
    (
        re.compile(r"\bpickle\.loads?\s*\("),
        "MEDIUM",
        "Untrusted pickle deserialization can be unsafe.",
    ),
    (
        re.compile(r"\bhashlib\.md5\s*\("),
        "LOW",
        "MD5 is weak for security-sensitive hashing.",
    ),
    (
        re.compile(r"\b(password|secret|api[_-]?key)\b\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        "MEDIUM",
        "Possible hardcoded credential.",
    ),
)


def scan_file(file_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return findings

    for line_number, line in enumerate(lines, start=1):
        for pattern, severity, message in RULES:
            if pattern.search(line):
                findings.append(
                    Finding(
                        file_path=str(file_path),
                        line_number=line_number,
                        severity=severity,
                        message=message,
                        pattern=pattern.pattern,
                    )
                )
    return findings


def scan_path(path: Path) -> list[Finding]:
    all_findings: list[Finding] = []
    if path.is_file():
        return scan_file(path)

    for file_path in path.rglob("*"):
        if not file_path.is_file():
            continue
        if ".git" in file_path.parts:
            continue
        all_findings.extend(scan_file(file_path))
    return all_findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple vulnerability scanner")
    parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    findings = scan_path(Path(args.path))

    if args.json:
        print(json.dumps([asdict(finding) for finding in findings], indent=2))
    else:
        if not findings:
            print("No findings.")
        for finding in findings:
            print(
                f"[{finding.severity}] {finding.file_path}:{finding.line_number} "
                f"{finding.message}"
            )

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
