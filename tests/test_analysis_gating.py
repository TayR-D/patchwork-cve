import json
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pipeline"))

import analyze
import export
import make_datasheet
import pass_c
import score_agreement


def pass_record(*, analyzable=True, cwe="CWE-79", finish="STOP", parse_error=None):
    return {
        "analysis": {
            "analyzable": analyzable,
            "cwe_primary": cwe,
            "patch_sufficient": True,
        },
        "finish": finish,
        "parse_error": parse_error,
    }


class ResponseSchemaTests(unittest.TestCase):
    def test_cwe_can_be_omitted_or_null_for_refusal(self):
        self.assertTrue(analyze.SCHEMA["properties"]["cwe_primary"]["nullable"])
        self.assertNotIn("cwe_primary", analyze.SCHEMA["required"])
        self.assertIn("set cwe_primary=null", analyze.PROMPT)


class AnalysisUsabilityTests(unittest.TestCase):
    def test_complete_opted_in_analysis_is_usable(self):
        self.assertTrue(score_agreement.analysis_usable(pass_record()))

    def test_refusal_is_not_usable_even_with_forced_cwe(self):
        self.assertFalse(score_agreement.analysis_usable(
            pass_record(analyzable=False, cwe="CWE-79")))

    def test_missing_or_invalid_cwe_is_not_usable(self):
        self.assertFalse(score_agreement.analysis_usable(pass_record(cwe=None)))
        self.assertFalse(score_agreement.analysis_usable(pass_record(cwe="CWE-unknown")))
        self.assertFalse(score_agreement.analysis_usable(pass_record(cwe="CWE-99999")))

    def test_parse_error_or_non_stop_finish_is_not_usable(self):
        self.assertFalse(score_agreement.analysis_usable(
            pass_record(parse_error="parse:JSONDecodeError")))
        self.assertFalse(score_agreement.analysis_usable(
            pass_record(finish="MAX_TOKENS")))
        self.assertFalse(score_agreement.analysis_usable(pass_record(finish=None)))

    def test_duplicate_retry_selection_is_deterministic_and_prefers_usable(self):
        refused = pass_record(analyzable=False)
        refused.update({"shard": "z99", "_analysis_text": '{"analyzable":false}'})
        usable = pass_record()
        usable.update({"shard": "a01", "_analysis_text": '{"analyzable":true}'})
        selected = max(
            [refused, usable], key=score_agreement.canonical_record_key
        )
        self.assertIs(selected, usable)

    def test_bigquery_loader_rejects_stale_patch_rows(self):
        rows = [
            {
                "cve": "CVE-2099-0100",
                "analysis": json.dumps(pass_record()["analysis"]),
                "finish": "STOP",
                "parse_error": None,
                "shard": "a01",
                "model": "gemini-2.5-pro",
                "attempt_id": "a" * 32,
                "patch_sha256": "old",
                "input_sha256": "1" * 64,
            },
            {
                "cve": "CVE-2099-0100",
                "analysis": json.dumps(pass_record()["analysis"]),
                "finish": "STOP",
                "parse_error": None,
                "shard": "a02",
                "model": "gemini-2.5-pro",
                "attempt_id": "b" * 32,
                "patch_sha256": "current",
                "input_sha256": "2" * 64,
            },
        ]
        for row in rows:
            record = {
                **row,
                "analysis": json.loads(row["analysis"]),
            }
            row["record_sha256"] = score_agreement.batch.analysis_record_sha256(record)
        completed = mock.Mock(returncode=0, stdout=json.dumps(rows), stderr="")
        with mock.patch.object(score_agreement.subprocess, "run", return_value=completed):
            loaded = score_agreement.load_pass(
                "pass_a", {"CVE-2099-0100": "current"}
            )
        self.assertEqual(loaded["CVE-2099-0100"]["patch_sha256"], "current")


class AgreementGatingTests(unittest.TestCase):
    candidate = {"cwe_ids": ["CWE-79"]}

    def test_two_usable_analyses_receive_agreement_label(self):
        row = score_agreement.score_row(
            "CVE-TEST-1", pass_record(), pass_record(), self.candidate)

        self.assertTrue(row["crosscheck_usable"])
        self.assertEqual(row["analysis_status"], "crosschecked")
        self.assertEqual(row["relation"], "exact")
        self.assertEqual(row["cwe_final"], "CWE-79")
        self.assertEqual(row["label_source"], "agreement")

    def test_refused_crosscheck_becomes_single_model_unverified(self):
        row = score_agreement.score_row(
            "CVE-TEST-2",
            pass_record(),
            pass_record(analyzable=False, cwe="CWE-79"),
            self.candidate,
        )

        self.assertFalse(row["crosscheck_usable"])
        self.assertEqual(row["analysis_status"], "pro_only")
        self.assertIsNone(row["relation"])
        self.assertEqual(row["cwe_final"], "CWE-79")
        self.assertEqual(row["label_source"], "single_model_unverified")
        self.assertFalse(row["usable_flash"])

    def test_refused_primary_can_fall_back_only_to_usable_flash(self):
        row = score_agreement.score_row(
            "CVE-TEST-3",
            pass_record(analyzable=False, cwe="CWE-89"),
            pass_record(cwe="CWE-79"),
            self.candidate,
        )

        self.assertEqual(row["analysis_status"], "flash_only")
        self.assertEqual(row["cwe_final"], "CWE-79")
        self.assertEqual(row["label_source"], "single_model_unverified")
        self.assertFalse(row["analyzable_pro"])
        self.assertTrue(row["analyzable_flash"])

    def test_no_usable_analysis_has_no_label_or_relation(self):
        row = score_agreement.score_row(
            "CVE-TEST-4",
            pass_record(analyzable=False),
            None,
            self.candidate,
        )

        self.assertEqual(row["analysis_status"], "no_usable_analysis")
        self.assertFalse(row["crosscheck_usable"])
        self.assertFalse(row["pass_flash_present"])
        self.assertIsNone(row["relation"])
        self.assertIsNone(row["cwe_final"])
        self.assertIsNone(row["label_source"])

    def test_main_emits_every_candidate_but_adjudicates_only_usable_conflict(self):
        candidates = [
            {"cve": "CVE-TEST-10", "cwe_ids": ["CWE-79"]},
            {"cve": "CVE-TEST-11", "cwe_ids": ["CWE-79"]},
            {"cve": "CVE-TEST-12", "cwe_ids": ["CWE-79"]},
            {"cve": "CVE-TEST-13", "cwe_ids": []},
        ]
        pro = {
            "CVE-TEST-10": pass_record(cwe="CWE-79"),
            "CVE-TEST-11": pass_record(cwe="CWE-79"),
            "CVE-TEST-12": pass_record(cwe="CWE-79"),
        }
        flash = {
            "CVE-TEST-10": pass_record(cwe="CWE-79"),
            "CVE-TEST-11": pass_record(cwe="CWE-89"),
            "CVE-TEST-12": pass_record(analyzable=False, cwe="CWE-89"),
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir) / "out"
            out_dir.mkdir()
            (out_dir / "candidates.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in candidates), encoding="utf-8")
            with (mock.patch.object(score_agreement, "R", temp_dir),
                  mock.patch.object(score_agreement, "load_pass",
                                    side_effect=[pro, flash]),
                  mock.patch("builtins.print")):
                score_agreement.main()

            scored = [json.loads(line) for line in
                      (out_dir / "agreement.jsonl").read_text().splitlines()]
            adjudicate = json.loads((out_dir / "adjudicate_cves.json").read_text())

        self.assertEqual(len(scored), 4)
        self.assertEqual(adjudicate, ["CVE-TEST-11"])
        by_cve = {row["cve"]: row for row in scored}
        self.assertEqual(by_cve["CVE-TEST-12"]["analysis_status"], "pro_only")
        self.assertEqual(by_cve["CVE-TEST-13"]["analysis_status"],
                         "no_usable_analysis")


class AdjudicationGatingTests(unittest.TestCase):
    def test_refusal_cannot_be_adjudicated(self):
        self.assertFalse(pass_c.eligible_for_adjudication(
            pass_record(analyzable=False, cwe="CWE-79"),
            pass_record(cwe="CWE-89"),
        ))

    def test_agreement_cannot_be_adjudicated(self):
        self.assertFalse(pass_c.eligible_for_adjudication(
            pass_record(cwe="CWE-79"), pass_record(cwe="CWE-79")))

    def test_build_shard_skips_refused_pair(self):
        cve = "CVE-2099-0200"
        row = {"cve": cve, "n_commits": 1,
               "commits": [{"owner": "o", "repo": "r", "sha": "a"}]}
        with tempfile.TemporaryDirectory() as temp_dir:
            patch_dir = Path(temp_dir) / "out" / "patches"
            patch_dir.mkdir(parents=True)
            (patch_dir / f"{cve}.patch").write_text("diff --git a/a b/a\n", encoding="utf-8")
            shard = {"id": "c01", "cves": [cve], "thinking": 0}
            pro = {cve: pass_record(analyzable=False, cwe="CWE-79")}
            flash = {cve: pass_record(cwe="CWE-89")}

            with (mock.patch.object(pass_c, "R", temp_dir),
                  mock.patch.object(pass_c.batch, "gs") as gs,
                  mock.patch.object(pass_c.adjudicate, "build_adj_request") as build):
                count = pass_c.build_shard(shard, {cve: row}, pro, flash)

            self.assertEqual(count, 0)
            build.assert_not_called()
            gs.assert_called_once()
            slots = json.loads((Path(temp_dir) / "out" / "batch_in" /
                                f"c01.{shard['attempt_id']}.slots.json").read_text())
            self.assertEqual(slots["rows"], [])

    def test_build_shard_rejects_unverified_patch_even_for_valid_conflict(self):
        cve = "CVE-2099-0201"
        row = {"cve": cve, "n_commits": 1,
               "commits": [{"owner": "o", "repo": "r", "sha": "a"}]}
        with tempfile.TemporaryDirectory() as temp_dir:
            patch_dir = Path(temp_dir) / "out" / "patches"
            patch_dir.mkdir(parents=True)
            (patch_dir / f"{cve}.patch").write_text("diff --git a/a b/a\n")
            shard = {"id": "c01", "cves": [cve], "thinking": 0}
            pro = {cve: pass_record(cwe="CWE-79")}
            flash = {cve: pass_record(cwe="CWE-89")}

            with (mock.patch.object(pass_c, "R", temp_dir),
                  mock.patch.object(pass_c.batch, "R", temp_dir),
                  mock.patch.object(pass_c.batch, "gs"),
                  mock.patch.object(pass_c.adjudicate, "build_adj_request") as build):
                count = pass_c.build_shard(shard, {cve: row}, pro, flash)

            self.assertEqual(count, 0)
            build.assert_not_called()

    def test_analysis_cache_is_invalidated_when_selected_pair_changes(self):
        cve = "CVE-2099-0202"
        raw = b"patch"
        row = {"cve": cve, "n_commits": 1,
               "commits": [{"owner": "o", "repo": "r", "sha": "a"}]}
        patch_sha = hashlib.sha256(raw).hexdigest()
        candidate_sha = pass_c.batch.fetch_patches.candidate_fingerprint(row, patch_sha)
        status = {
            "cve": cve, "status": "ok", "patch_format": "github-commit-dot-patch-v1",
            "n_fetched": 1, "n_commits": 1, "patch_sha256": patch_sha,
            "patch_commits": [{**row["commits"][0], "included": True,
                               "fetch_status": "ok"}],
        }
        def source_record(model, shard, marker, cwe):
            record = {
                "cve": cve, "model": model, "shard": shard,
                "attempt_id": marker * 32, "patch_sha256": patch_sha,
                "candidate_fingerprint": candidate_sha,
                "input_sha256": marker * 64,
                "analysis": pass_record(cwe=cwe)["analysis"],
                "finish": "STOP", "parse_error": None,
            }
            record["record_sha256"] = pass_c.batch.analysis_record_sha256(record)
            return record

        current_pro = source_record("gemini-2.5-pro", "a01", "1", "CWE-79")
        flash = source_record("gemini-2.5-flash", "b01", "2", "CWE-89")

        def agreement(pro_record_sha):
            pair = score_agreement.analysis_pair_sha256(
                cve, patch_sha,
                {"record_sha256": pro_record_sha,
                 "candidate_fingerprint": candidate_sha},
                {"record_sha256": flash["record_sha256"],
                 "candidate_fingerprint": candidate_sha},
            )
            return {
                "cve": cve, "label_source": "needs_adjudication",
                "crosscheck_usable": True, "analysis_patch_sha256": patch_sha,
                "analysis_candidate_fingerprint": candidate_sha,
                "pass_pro_record_sha256": pro_record_sha,
                "pass_flash_record_sha256": flash["record_sha256"],
                "analysis_pair_sha256": pair,
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            out = Path(temp_dir) / "out"
            patches = out / "patches"
            patches.mkdir(parents=True)
            (patches / f"{cve}.patch").write_bytes(raw)
            (out / "candidates.jsonl").write_text(json.dumps(row) + "\n")
            (out / "adjudicate_cves.json").write_text(json.dumps([cve]))
            (out / "fetch_status.jsonl").write_text(json.dumps(status) + "\n")
            agreement_path = out / "agreement.jsonl"
            agreement_path.write_text(
                json.dumps(agreement(current_pro["record_sha256"])) + "\n"
            )

            def fake_load(stage, *args):
                return {cve: current_pro if stage == "pass_a" else flash}

            cache = out / "pass_c_analyses.json"
            with (mock.patch.object(pass_c, "R", temp_dir),
                  mock.patch.object(pass_c, "CACHE", str(cache)),
                  mock.patch.object(score_agreement, "load_pass",
                                    side_effect=fake_load) as load):
                pass_c.load_analyses()
                pass_c.load_analyses()
                self.assertEqual(load.call_count, 2)

                current_pro = source_record(
                    "gemini-2.5-pro", "a02", "3", "CWE-79"
                )
                agreement_path.write_text(
                    json.dumps(agreement(current_pro["record_sha256"])) + "\n"
                )
                pass_c.load_analyses()
                self.assertEqual(load.call_count, 4)


class ExportContractTests(unittest.TestCase):
    def test_export_surfaces_per_model_and_crosscheck_state(self):
        for field in ("analyzable_pro", "analyzable_flash", "usable_pro",
                      "usable_flash", "crosscheck_usable", "analysis_status"):
            self.assertIn(field, export.FINAL_SQL)
        self.assertIn("LEFT JOIN a", export.FINAL_SQL)
        self.assertIn("g.crosscheck_usable IS TRUE", export.FINAL_SQL)
        self.assertNotIn("g.cwe_final, g.cwe_pro", export.FINAL_SQL)

    def test_export_deduplicates_retries_and_binds_every_join_to_patch(self):
        self.assertIn("ROW_NUMBER() OVER", export.FINAL_SQL)
        self.assertIn("PARTITION BY p.cve, p.patch_sha256", export.FINAL_SQL)
        self.assertIn("c.patch_sha256 = a.patch_sha256", export.FINAL_SQL)
        self.assertIn("c.patch_sha256 = b.patch_sha256", export.FINAL_SQL)
        self.assertIn("c.patch_sha256 = g.analysis_patch_sha256", export.FINAL_SQL)
        self.assertIn(
            "c.candidate_fingerprint = g.analysis_candidate_fingerprint",
            export.FINAL_SQL,
        )
        self.assertIn("c.patch_sha256 = adj.patch_sha256", export.FINAL_SQL)
        self.assertIn("g.pass_pro_record_sha256 = a.record_sha256", export.FINAL_SQL)
        self.assertIn("g.pass_flash_record_sha256 = b.record_sha256", export.FINAL_SQL)
        self.assertIn("g.analysis_pair_sha256 = adj.analysis_pair_sha256", export.FINAL_SQL)

    def test_adjudication_must_complete_and_return_a_known_cwe(self):
        gate = export.adjudication_usable_sql("p")
        self.assertIn("p.finish = 'STOP'", gate)
        self.assertIn("p.parse_error IS NULL", gate)
        self.assertIn("$.cwe_final", gate)
        self.assertIn("IN UNNEST", gate)
        self.assertIn("BETWEEN 0 AND 1", gate)

    def test_datasheet_relations_exclude_unusable_pairs(self):
        rows = [
            {"relation": "exact", "crosscheck_usable": True,
             "analysis_status": "crosschecked"},
            {"relation": "conflict", "crosscheck_usable": False,
             "analysis_status": "pro_only"},
            {"relation": None, "crosscheck_usable": False,
             "analysis_status": "no_usable_analysis"},
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "agreement.jsonl"
            path.write_text("".join(json.dumps(row) + "\n" for row in rows),
                            encoding="utf-8")
            relations, statuses = make_datasheet.agreement_counters(path)

        self.assertEqual(relations, {"exact": 1})
        self.assertEqual(statuses["crosschecked"], 1)
        self.assertEqual(statuses["pro_only"], 1)


if __name__ == "__main__":
    unittest.main()
