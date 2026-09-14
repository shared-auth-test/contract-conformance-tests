import subprocess
import unittest


class GeneratedEvidenceHygieneTests(unittest.TestCase):
    def test_repository_generated_evidence_is_clean(self):
        result = subprocess.run(
            ["python", "scripts/check_generated_evidence_hygiene.py"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("generated evidence hygiene: ok", result.stdout)


if __name__ == "__main__":
    unittest.main()
