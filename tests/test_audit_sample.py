from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pipeline"))

import make_audit_sample


class AuditSampleTests(unittest.TestCase):
    ROWS = [
        {
            "cve": f"CVE-TEST-{number}",
            "label_source": label,
            "ecosystem": ecosystem,
        }
        for number, (label, ecosystem) in enumerate(
            [
                ("agreement", "npm"),
                ("agreement", "npm"),
                ("agreement", "PyPI"),
                ("agreement", "Maven"),
                ("agreement_specific", "npm"),
                ("agreement_specific", "PyPI"),
                ("adjudicated", "Go"),
                ("adjudicated", "Maven"),
            ],
            start=1,
        )
    ]

    def test_sample_is_stable_and_covers_every_label_source(self):
        first = make_audit_sample.sample_rows(self.ROWS, size=5, seed="test")
        second = make_audit_sample.sample_rows(list(reversed(self.ROWS)), size=5, seed="test")
        self.assertEqual(first, second)
        self.assertEqual(len(first), 5)
        self.assertEqual(
            {row["label_source"] for row in first},
            {"agreement", "agreement_specific", "adjudicated"},
        )

    def test_too_small_sample_cannot_claim_full_stratification(self):
        with self.assertRaisesRegex(ValueError, "cannot cover all"):
            make_audit_sample.sample_rows(self.ROWS, size=2)

    def test_oversized_sample_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "exceeds dataset size"):
            make_audit_sample.sample_rows(self.ROWS, size=20)


if __name__ == "__main__":
    unittest.main()
