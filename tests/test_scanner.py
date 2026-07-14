import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scanner import scan_path


class ScannerTests(unittest.TestCase):
    def test_detects_eval_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample = Path(tmp_dir) / "app.py"
            sample.write_text("result = eval(user_input)\n", encoding="utf-8")

            findings = scan_path(Path(tmp_dir))

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "HIGH")
            self.assertIn("eval", findings[0].pattern)

    def test_cli_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample = Path(tmp_dir) / "secrets.py"
            sample.write_text('password = "abc123"\n', encoding="utf-8")

            result = subprocess.run(
                ["python3", "scanner.py", tmp_dir, "--json"],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 1)
            data = json.loads(result.stdout)
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["severity"], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
