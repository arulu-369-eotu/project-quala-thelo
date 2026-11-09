"""Acceptance checks for the additive lab; no changes to legacy UQL tests."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/uql_learning_lab.py"
SPEC = importlib.util.spec_from_file_location("uql_learning_lab", SCRIPT)
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class LearningLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs = {"t1_us": 100.0, "t2_us": 80.0, "compare_t2_us": 120.0,
                      "idle_us": [0, 10, 80, 160], "distance": 3}
        cls.envelope = lab.build_report(cls.inputs)

    def invoke(self, *arguments):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, arguments)],
                              cwd=ROOT, capture_output=True, text=True, timeout=60)

    def test_generated_report_round_trip(self):
        report = lab.verify(self.envelope)
        self.assertEqual(set(report["results"]), set(lab.CHECKS))
        self.assertEqual(report["results"]["crypto"]["status"], "not_run")
        self.assertEqual(report["inputs"], self.inputs)

    def test_coherence_compares_the_existing_public_model(self):
        result = self.envelope["report"]["results"]["coherence"]
        if result["status"] == "blocked":
            self.skipTest("public model dependency unavailable; use the documented package environment")
        reference, comparison = result["details"]["scenarios"]
        self.assertEqual(reference["survival"][0], 1)
        self.assertEqual(comparison["survival"][0], 1)
        self.assertEqual(comparison["effective_coherence_us"], 100)
        self.assertGreater(comparison["survival"][2], reference["survival"][2])
        self.assertAlmostEqual(reference["survival"][2], 0.36787944117144233)

    def test_edited_report_fails_integrity(self):
        changed = copy.deepcopy(self.envelope)
        changed["report"]["runtime"]["python"] = "0.0.0"
        with self.assertRaisesRegex(ValueError, "integrity"):
            lab.verify(changed)

    def test_rehashed_inconsistent_model_is_rejected(self):
        changed = copy.deepcopy(self.envelope)
        result = changed["report"]["results"]["coherence"]
        if result["status"] == "blocked":
            self.skipTest("public model dependency unavailable")
        result["details"]["scenarios"][0]["survival"][0] = 0.5
        changed["sha256"] = lab.digest(changed["report"])
        with self.assertRaisesRegex(ValueError, "curve"):
            lab.verify(changed)

    def test_rehashed_source_mismatch_is_rejected(self):
        changed = copy.deepcopy(self.envelope)
        changed["report"]["provenance"]["sources"][lab.SOURCE_PATHS[0]] = "0" * 64
        changed["sha256"] = lab.digest(changed["report"])
        with self.assertRaisesRegex(ValueError, "fingerprints"):
            lab.verify(changed)

    def test_crypto_cannot_be_promoted_to_passed(self):
        changed = copy.deepcopy(self.envelope)
        changed["report"]["results"]["crypto"] = {"status": "passed", "details": {}}
        changed["sha256"] = lab.digest(changed["report"])
        with self.assertRaisesRegex(ValueError, "cryptographic"):
            lab.verify(changed)

    def test_invalid_numeric_inputs_are_rejected_before_probes(self):
        for invalid in (float("nan"), float("inf"), -1, 0, True, "100", 10 ** 1000):
            with self.subTest(invalid=repr(invalid)[:40]):
                inputs = dict(self.inputs, t1_us=invalid)
                with self.assertRaises(ValueError):
                    lab.validate_inputs(inputs)

    def test_input_size_distance_and_extra_fields_are_bounded(self):
        for change in ({"idle_us": []}, {"idle_us": [0] * 65}, {"distance": 1001},
                       {"distance": True}, {"private_source": "unrelated"}):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    lab.validate_inputs(dict(self.inputs, **change))

    def test_unknown_report_fields_are_rejected_even_when_rehashed(self):
        changed = copy.deepcopy(self.envelope)
        changed["report"]["extra"] = "unapproved field"
        changed["sha256"] = lab.digest(changed["report"])
        with self.assertRaises(ValueError):
            lab.verify(changed)

    def test_json_duplicates_nonfinite_values_and_oversize_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            for raw in (b'{"report":{},"report":{}}', b'{"value":NaN}',
                        b" " * (lab.MAX_REPORT_BYTES + 1)):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    lab.load_report(path)

    def test_public_source_allowlist_excludes_other_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in lab.SOURCE_PATHS:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("synthetic public fixture", encoding="utf-8")
            unrelated = root / "private-research.txt"
            unrelated.write_text("must remain unread", encoding="utf-8")
            self.assertEqual(set(lab.public_sources(root)), set(lab.SOURCE_PATHS))
            first = root / lab.SOURCE_PATHS[0]
            first.unlink()
            first.symlink_to(unrelated)
            with self.assertRaisesRegex(ValueError, "symlink"):
                lab.public_sources(root)

    def test_cli_report_replay_and_fail_closed_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            generated = self.invoke("run", "--compare-t2-us", "120", "--output", path)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            checked = self.invoke("verify", path, "--replay")
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertIn("observations match", checked.stdout)
            gated = self.invoke("verify", path, "--require-pass", "crypto")
            self.assertEqual(gated.returncode, 2)
            self.assertIn("required exercise did not pass", gated.stderr)

    def test_output_file_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "existing.json"
            path.write_text("preserve this", encoding="utf-8")
            result = self.invoke("run", "--output", path)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(path.read_text(encoding="utf-8"), "preserve this")

    def test_verify_needs_no_third_party_imports(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            path.write_text(json.dumps(self.envelope), encoding="utf-8")
            result = subprocess.run([sys.executable, "-S", str(SCRIPT), "verify", str(path)],
                                    cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_dependencies_cannot_become_passed_exercises(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            result = subprocess.run([sys.executable, "-S", str(SCRIPT), "run", "--output", str(path)],
                                    cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = lab.verify(lab.load_report(path))
            for name in ("declarations", "memory", "coherence", "surface", "dd"):
                self.assertEqual(report["results"][name]["status"], "blocked")

    def test_cli_rejects_nonfinite_and_malformed_input(self):
        result = self.invoke("run", "--t1-us", "nan")
        self.assertEqual(result.returncode, 2)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.json"
            path.write_text("not json", encoding="utf-8")
            result = self.invoke("verify", path)
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
