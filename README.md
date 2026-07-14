# vuln-scanner

A lightweight, static vulnerability scanner that can be used in local development or CI to catch risky patterns early.

## Features

- Scans files or directories recursively
- Detects common high-risk patterns:
  - Hardcoded secrets (AWS keys, private keys, password literals)
  - Dynamic code execution (`eval`, `exec`)
  - Command injection sinks (`subprocess(..., shell=True)`, `os.system`)
  - Unsafe deserialization (`pickle.loads`)
- Supports text and JSON output
- Supports severity filtering and CI-friendly failure behavior

## Usage

```bash
python scanner.py /path/to/project
```

Useful options:

- `--format text|json` (default: `text`)
- `--min-severity low|medium|high|critical` (default: `low`)
- `--fail-on low|medium|high|critical` (default: `high`)
- `--max-file-size <bytes>` (default: `1048576`)

Example (CI):

```bash
python scanner.py . --format json --fail-on medium
```

## Run tests

```bash
python -m unittest discover -v
```

## Note

This scanner is signature-based and intended as a first-pass guardrail. It should be combined with dependency scanning, SAST, and runtime protections for stronger security coverage.
