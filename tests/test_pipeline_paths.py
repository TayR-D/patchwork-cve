import json
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pipeline"))

import build_corpus
import batch
import fetch_patches
import make_shards


class CleanClonePathTests(unittest.TestCase):
    def test_corpus_default_matches_downstream_out_path(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(build_corpus, "R", directory), \
                    mock.patch.object(build_corpus, "ECOS", []), \
                    mock.patch.dict(os.environ, {}, clear=True):
                build_corpus.main()
            output = Path(directory) / "out" / "candidates.jsonl"
            self.assertTrue(output.exists())
            self.assertEqual(output.read_text(), "")

    def test_shard_planner_creates_clean_clone_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(make_shards, "R", directory), \
                    mock.patch.object(make_shards, "eligible", return_value=[]):
                make_shards.main()
            state = json.loads(
                (Path(directory) / "state" / "shards.json").read_text()
            )
            assignment = json.loads(
                (Path(directory) / "out" / "shard_assign.json").read_text()
            )
            self.assertEqual(state["corpus"], 0)
            self.assertEqual(state["shards"], [])
            self.assertEqual(assignment, {})

    def test_batch_patch_path_requires_matching_versioned_provenance(self):
        raw = b"verified patch"
        candidate = {
            "cve": "CVE-2099-0300",
            "n_commits": 1,
            "commits": [{"owner": "org", "repo": "repo", "sha": "abc"}],
        }
        status = {
            "cve": candidate["cve"],
            "status": "ok",
            "patch_format": fetch_patches.PATCH_FORMAT,
            "n_fetched": 1,
            "n_commits": 1,
            "patch_sha256": hashlib.sha256(raw).hexdigest(),
            "patch_commits": [{
                **candidate["commits"][0],
                "included": True,
                "fetch_status": "ok",
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            patch_dir = Path(directory) / "out" / "patches"
            patch_dir.mkdir(parents=True)
            patch = patch_dir / f"{candidate['cve']}.patch"
            patch.write_bytes(raw)
            with mock.patch.object(batch, "R", directory):
                self.assertEqual(
                    batch.verified_patch_path(candidate, {candidate["cve"]: status}),
                    str(patch),
                )
                patch.write_bytes(b"stale")
                self.assertIsNone(
                    batch.verified_patch_path(candidate, {candidate["cve"]: status})
                )

    def test_batch_harvest_carries_indexed_patch_hash(self):
        cve = "CVE-2099-0301"
        attempt_id = "a" * 32
        patch_sha256 = "b" * 64
        candidate_fingerprint = "c" * 64
        response = {
            "request": {"contents": [{"parts": [{"text": f"CVE: {cve}\n"}]}]},
            "response": {
                "candidates": [{
                    "content": {"parts": [{"text": '{"analyzable":false}'}]},
                    "finishReason": "STOP",
                }],
                "usageMetadata": {},
            },
        }
        input_sha256 = batch.attach_request_provenance(
            response["request"], attempt_id, patch_sha256,
            candidate_fingerprint,
        )
        with tempfile.TemporaryDirectory() as directory:
            index_dir = Path(directory) / "out" / "batch_in"
            index_dir.mkdir(parents=True)
            (index_dir / f"a01.{attempt_id}.index.json").write_text(json.dumps({
                "shard": "a01",
                "model": "gemini-2.5-pro",
                "attempt_id": attempt_id,
                "rows": [{"cve": cve, "patch_sha256": patch_sha256,
                          "candidate_fingerprint": candidate_fingerprint,
                          "input_sha256": input_sha256}],
            }))

            def fake_gs(command, *args, **kwargs):
                if command == "ls":
                    return "gs://bucket/prediction.results.jsonl\n"
                return json.dumps(response) + "\n"

            with (mock.patch.object(batch, "R", directory),
                  mock.patch.object(batch, "gs", side_effect=fake_gs)):
                records, errors, _ = batch.harvest(
                    "a01", "gemini-2.5-pro", attempt_id
                )

        self.assertEqual(errors, [])
        self.assertEqual(records[0]["cve"], cve)
        self.assertEqual(records[0]["patch_sha256"], patch_sha256)
        self.assertEqual(
            records[0]["candidate_fingerprint"], candidate_fingerprint
        )
        self.assertEqual(records[0]["input_sha256"], input_sha256)
        self.assertTrue(records[0]["record_sha256"])

    def test_batch_build_uses_an_immutable_attempt_path_and_echoed_provenance(self):
        attempt_id = "9" * 32
        raw = b"diff --git a/a b/a\n"
        candidate = {
            "cve": "CVE-2099-0303", "n_commits": 1,
            "ecosystem": "PyPI", "packages": ["demo"], "summary": "summary",
            "details": "details", "cvss": None, "cwe_ids": [],
            "commits": [{"owner": "org", "repo": "repo", "sha": "abc"}],
        }
        patch_sha = hashlib.sha256(raw).hexdigest()
        status = {
            "cve": candidate["cve"], "status": "ok",
            "patch_format": fetch_patches.PATCH_FORMAT,
            "n_fetched": 1, "n_commits": 1, "patch_sha256": patch_sha,
            "patch_commits": [{**candidate["commits"][0], "included": True,
                               "fetch_status": "ok"}],
        }
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "out"
            patches = out / "patches"
            patches.mkdir(parents=True)
            (patches / f"{candidate['cve']}.patch").write_bytes(raw)
            (out / "fetch_status.jsonl").write_text(json.dumps(status) + "\n")
            uuid_value = mock.Mock(hex=attempt_id)
            with (mock.patch.object(batch, "R", directory),
                  mock.patch.object(batch, "BUCKET", "gs://bucket"),
                  mock.patch.object(batch.uuid, "uuid4", return_value=uuid_value),
                  mock.patch.object(batch, "gs") as gs):
                local, kept, missing, actual_attempt = batch.build(
                    [candidate], "a01", "gemini-2.5-pro", 1024
                )

            self.assertEqual((kept, missing, actual_attempt), (1, 0, attempt_id))
            self.assertTrue(local.endswith(f"a01.{attempt_id}.jsonl"))
            gs.assert_called_once_with(
                "cp", local, f"gs://bucket/batch_in/a01/{attempt_id}.jsonl"
            )
            request = json.loads(Path(local).read_text())["request"]
            provenance = batch.verified_request_provenance(request, attempt_id)
            self.assertEqual(provenance["patch_sha256"], patch_sha)

    def test_bigquery_schemas_pin_nullable_and_temporal_types(self):
        def fields(name):
            schema = json.loads((ROOT / "schema" / name).read_text())
            return {field["name"]: field for field in schema}

        candidates = fields("bq_candidates.json")
        agreement = fields("bq_agreement.json")
        passes = fields("bq_pass.json")
        self.assertEqual(candidates["published"]["type"], "STRING")
        self.assertEqual(candidates["patch_bytes"]["type"], "INTEGER")
        self.assertEqual(agreement["analyzable_pro"]["type"], "BOOLEAN")
        self.assertEqual(agreement["analyzable_flash"]["type"], "BOOLEAN")
        self.assertEqual(passes["analysis"]["type"], "STRING")
        self.assertIn("candidate_fingerprint", passes)

    def test_embedded_batch_provenance_detects_mixed_or_changed_attempts(self):
        attempt = "d" * 32
        body = {"contents": [{"parts": [{"text": "CVE: CVE-2099-0302\n"}]}]}
        batch.attach_request_provenance(body, attempt, "e" * 64, "f" * 64)
        verified = batch.verified_request_provenance(body, attempt)
        self.assertEqual(verified["patch_sha256"], "e" * 64)

        with self.assertRaises(RuntimeError):
            batch.verified_request_provenance(body, "0" * 32)
        body["contents"][0]["parts"][0]["text"] += "changed"
        with self.assertRaises(RuntimeError):
            batch.verified_request_provenance(body, attempt)

    def test_harvest_rejects_mutated_pass_c_pair_sidecar(self):
        cve = "CVE-2099-0304"
        attempt = "4" * 32
        patch_sha, candidate_sha = "5" * 64, "6" * 64
        pro_sha, flash_sha = "7" * 64, "8" * 64
        pair_sha = batch.source_pair_sha256(
            cve, patch_sha, candidate_sha, pro_sha, flash_sha
        )
        request = {"contents": [{"parts": [{"text": f"CVE: {cve}\n"}]}]}
        input_sha = batch.attach_request_provenance(
            request, attempt, patch_sha, candidate_sha,
            pair_sha, pro_sha, flash_sha,
        )
        output = {"request": request, "status": {"code": 13}}
        with tempfile.TemporaryDirectory() as directory:
            index_dir = Path(directory) / "out" / "batch_in"
            index_dir.mkdir(parents=True)
            (index_dir / f"c01.{attempt}.index.json").write_text(json.dumps({
                "shard": "c01", "model": "gemini-2.5-pro",
                "attempt_id": attempt,
                "rows": [{
                    "cve": cve, "patch_sha256": patch_sha,
                    "candidate_fingerprint": candidate_sha,
                    "input_sha256": input_sha,
                    "analysis_pair_sha256": "0" * 64,
                    "pass_pro_record_sha256": pro_sha,
                    "pass_flash_record_sha256": flash_sha,
                }],
            }))

            def fake_gs(command, *args, **kwargs):
                if command == "ls":
                    return "gs://bucket/prediction.results.jsonl\n"
                return json.dumps(output) + "\n"

            with (mock.patch.object(batch, "R", directory),
                  mock.patch.object(batch, "gs", side_effect=fake_gs),
                  self.assertRaises(RuntimeError)):
                batch.harvest("c01", "gemini-2.5-pro", attempt)


if __name__ == "__main__":
    unittest.main()
