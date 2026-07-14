import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


class ScannerCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parents[1]
        self.scanner = self.repo_root / "scanner.py"

    def test_detects_command_injection_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "app.py"
            file_path.write_text("import subprocess\nsubprocess.run(cmd, shell=True)\n", encoding="utf-8")

            result = subprocess.run(
                [sys.executable, str(self.scanner), str(file_path), "--format", "json"],
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 1)
            payload = json.loads(result.stdout)
            self.assertGreaterEqual(payload["total_findings"], 1)
            self.assertEqual(payload["findings"][0]["rule_id"], "COMMAND_SHELL_TRUE")

    def test_respects_min_severity_filter(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "settings.py"
            file_path.write_text("password = 'secret1234'\n", encoding="utf-8")

            result = subprocess.run(
                [sys.executable, str(self.scanner), str(file_path), "--format", "json", "--min-severity", "high"],
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["total_findings"], 0)

    def test_target_missing_returns_error(self) -> None:
        result = subprocess.run(
            [sys.executable, str(self.scanner), "/tmp/does-not-exist-vuln-scan"],
            check=False,
            text=True,
            capture_output=True,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("Target does not exist", result.stderr)


if __name__ == "__main__":
    unittest.main()
