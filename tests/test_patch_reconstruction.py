import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fetch_full = load_module("fetch_full", ROOT / "fetch_full.py")
fetch_patches = load_module("fetch_patches", ROOT / "pipeline" / "fetch_patches.py")
export = load_module("patchwork_export", ROOT / "pipeline" / "export.py")


class CollectorTests(unittest.TestCase):
    def test_successful_status_round_trips_through_release_reconstructor(self):
        commits = [
            {"owner": "org", "repo": "one", "sha": "aaa", "ref_type": "FIX"},
            {"owner": "org", "repo": "two", "sha": "bbb", "ref_type": "FIX"},
        ]
        bodies = {
            "one": b"first\xff",
            "two": b"z" * (fetch_patches.MAX_RAW + 1),
        }

        def collector_fetch(url, timeout=45, tries=3, token=None):
            repo = url.split("/")[4]
            return bodies[repo], None

        def reconstruction_fetch(owner, repo, sha, token=None, max_bytes=None):
            return bodies[repo][:max_bytes + 1]

        with tempfile.TemporaryDirectory() as patch_dir:
            with mock.patch.object(fetch_patches, "PATCH_DIR", patch_dir), \
                    mock.patch.object(fetch_patches, "fetch_one", side_effect=collector_fetch):
                status_row = fetch_patches.process({
                    "cve": "CVE-2099-0001",
                    "commits": commits,
                    "n_commits": len(commits),
                })
            collected = Path(patch_dir, "CVE-2099-0001.patch").read_bytes()

        reconstructed, reconstruction_status = fetch_full.reconstruct(
            status_row, fetcher=reconstruction_fetch
        )
        self.assertEqual(status_row["status"], "ok")
        self.assertEqual(reconstruction_status, "ok")
        self.assertEqual(reconstructed, collected)
        self.assertEqual(hashlib.sha256(reconstructed).hexdigest(), status_row["patch_sha256"])

    def test_process_records_order_truncation_and_failed_commit(self):
        commits = [
            {"owner": "org", "repo": "one", "sha": "aaa", "ref_type": "FIX"},
            {"owner": "org", "repo": "two", "sha": "bbb", "ref_type": "FIX"},
            {"owner": "org", "repo": "three", "sha": "ccc", "ref_type": "FIX"},
        ]
        first = b"a" * (fetch_patches.MAX_RAW + 1)
        third = b"third\xff"

        def fake_fetch(url, timeout=45, tries=3, token=None):
            if "/aaa.patch" in url:
                return first, None
            if "/bbb.patch" in url:
                return None, "http404"
            return third, None

        with tempfile.TemporaryDirectory() as patch_dir:
            with mock.patch.object(fetch_patches, "PATCH_DIR", patch_dir), \
                    mock.patch.object(fetch_patches, "fetch_one", side_effect=fake_fetch):
                result = fetch_patches.process({
                    "cve": "CVE-2099-0002",
                    "commits": commits,
                    "n_commits": len(commits),
                })
            expected = first[:fetch_patches.MAX_RAW] + b"\n" + third
            self.assertFalse(Path(patch_dir, "CVE-2099-0002.patch").exists())

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["patch_format"], fetch_full.PATCH_FORMAT)
        self.assertEqual(result["patch_sha256"], hashlib.sha256(expected).hexdigest())
        self.assertTrue(result["patch_truncated"])
        self.assertTrue(result["patch_partial_fetch"])
        self.assertFalse(result["patch_complete"])
        self.assertEqual([item["position"] for item in result["patch_commits"]], [0, 1, 2])
        self.assertTrue(result["patch_commits"][0]["truncated"])
        self.assertTrue(result["patch_commits"][0]["response_size_is_lower_bound"])
        self.assertFalse(result["patch_commits"][1]["included"])
        self.assertEqual(result["patch_commits"][1]["fetch_error"], "http404")

    def test_resume_requires_versioned_status_and_matching_file(self):
        body = b"verified"
        status = {
            "cve": "CVE-2099-0003",
            "status": "ok",
            "patch_format": fetch_patches.PATCH_FORMAT,
            "n_fetched": 1,
            "n_commits": 1,
            "patch_commits": [{"included": True, "fetch_status": "ok"}],
            "patch_sha256": hashlib.sha256(body).hexdigest(),
        }
        with tempfile.TemporaryDirectory() as patch_dir:
            with mock.patch.object(fetch_patches, "PATCH_DIR", patch_dir):
                candidate = {
                    "cve": "CVE-2099-0003",
                    "n_commits": 1,
                    "commits": [{"owner": "org", "repo": "repo", "sha": "abc"}],
                }
                status["patch_commits"][0].update(candidate["commits"][0])
                self.assertFalse(fetch_patches.status_matches_patch(status, candidate))
                Path(patch_dir, "CVE-2099-0003.patch").write_bytes(body)
                self.assertTrue(fetch_patches.status_matches_patch(status, candidate))
                Path(patch_dir, "CVE-2099-0003.patch").write_bytes(b"wrong")
                self.assertFalse(fetch_patches.status_matches_patch(status, candidate))
                changed = {
                    "cve": "CVE-2099-0003",
                    "n_commits": 1,
                    "commits": [{"owner": "org", "repo": "repo", "sha": "def"}],
                }
                self.assertFalse(fetch_patches.status_matches_patch(status, changed))
                legacy = {"cve": "CVE-2099-0003", "status": "ok"}
                self.assertFalse(fetch_patches.status_matches_patch(legacy, candidate))

    def test_collector_rejects_unsafe_cve_filename(self):
        with tempfile.TemporaryDirectory() as patch_dir, \
                mock.patch.object(fetch_patches, "PATCH_DIR", patch_dir):
            result = fetch_patches.process({
                "cve": "../../outside",
                "commits": [{"owner": "org", "repo": "repo", "sha": "abc"}],
                "n_commits": 1,
            })
        self.assertEqual(result["status"], "invalid_cve")

    def test_incomplete_final_status_fragment_is_preserved_and_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fetch_status.jsonl"
            path.write_bytes(
                b'{"cve":"CVE-2099-0003","status":"ok"}\n'
                b'{"cve":"CVE-2099-'
            )
            corrupt = fetch_patches.repair_trailing_status_fragment(path)

            self.assertEqual(
                path.read_bytes(), b'{"cve":"CVE-2099-0003","status":"ok"}\n'
            )
            self.assertEqual(Path(corrupt).read_bytes(), b'{"cve":"CVE-2099-')
            self.assertEqual(
                fetch_patches.load_latest_status(path)["CVE-2099-0003"]["status"],
                "ok",
            )


class ExportProvenanceTests(unittest.TestCase):
    def complete_status(self, raw=b"patch"):
        return {
            "cve": "CVE-2099-0004",
            "status": "ok",
            "n_fetched": 1,
            "n_commits": 1,
            "patch_format": fetch_patches.PATCH_FORMAT,
            "patch_representation": fetch_patches.PATCH_REPRESENTATION,
            "patch_joiner": "LF",
            "patch_max_bytes_per_commit": fetch_patches.MAX_RAW,
            "patch_sha256": hashlib.sha256(raw).hexdigest(),
            "patch_truncated": False,
            "patch_partial_fetch": False,
            "patch_complete": True,
            "patch_commits": [{
                "position": 0,
                "owner": "org",
                "repo": "repo",
                "sha": "abc",
                "included": True,
                "fetch_status": "ok",
            }],
        }

    def test_release_metadata_requires_complete_matching_provenance(self):
        candidate = {
            "cve": "CVE-2099-0004",
            "n_commits": 1,
            "commits": [{"owner": "org", "repo": "repo", "sha": "abc"}],
        }
        raw = b"patch"
        metadata = export.release_patch_metadata(candidate, self.complete_status(raw), raw)
        self.assertEqual(metadata["patch_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(metadata["patch_commits"][0]["sha"], "abc")

        partial = self.complete_status(raw)
        partial["status"] = "partial"
        partial["patch_partial_fetch"] = True
        self.assertIsNone(export.release_patch_metadata(candidate, partial, raw))
        self.assertIsNone(export.release_patch_metadata(
            candidate, self.complete_status(raw), b"changed"
        ))

    def test_fetch_status_is_last_row_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fetch_status.jsonl"
            path.write_text(
                '{"cve":"CVE-2099-0004","status":"ok"}\n'
                '{"cve":"CVE-2099-0004","status":"partial"}\n',
                encoding="utf-8",
            )
            latest = export.load_fetch_status(path)
        self.assertEqual(latest["CVE-2099-0004"]["status"], "partial")

    def test_export_ignores_only_an_incomplete_final_status_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fetch_status.jsonl"
            path.write_bytes(
                b'{"cve":"CVE-2099-0004","status":"ok"}\n{"cve":'
            )
            with mock.patch("builtins.print") as warning:
                latest = export.load_fetch_status(path)
            self.assertEqual(latest["CVE-2099-0004"]["status"], "ok")
            warning.assert_called_once()

            path.write_text('{"cve":\n{"cve":"CVE-2099-0004"}\n', encoding="utf-8")
            with self.assertRaises(RuntimeError):
                export.load_fetch_status(path)


class ReconstructionTests(unittest.TestCase):
    def record(self, expected=None):
        first = b"abc"
        second = b"uvwxyz"
        raw = first + b"\n" + second[:4]
        return {
            "cve": "CVE-2099-0005",
            "patch_format": fetch_full.PATCH_FORMAT,
            "patch_representation": fetch_full.PATCH_REPRESENTATION,
            "patch_joiner": "LF",
            "patch_max_bytes_per_commit": 4,
            "patch_sha256": expected or hashlib.sha256(raw).hexdigest(),
            "patch_commits": [
                {
                    "position": "2",
                    "owner": "org",
                    "repo": "second",
                    "sha": "bbb",
                    "representation": fetch_full.PATCH_REPRESENTATION,
                    "included": True,
                    "max_bytes": 4,
                    "bytes_kept": 4,
                    "collected_sha256": hashlib.sha256(second[:4]).hexdigest(),
                },
                {
                    "position": "1",
                    "owner": "org",
                    "repo": "omitted",
                    "sha": "zzz",
                    "representation": fetch_full.PATCH_REPRESENTATION,
                    "included": False,
                    "fetch_status": "error",
                },
                {
                    "position": "0",
                    "owner": "org",
                    "repo": "first",
                    "sha": "aaa",
                    "representation": fetch_full.PATCH_REPRESENTATION,
                    "included": True,
                    "max_bytes": 4,
                    "bytes_kept": 3,
                    "collected_sha256": hashlib.sha256(first).hexdigest(),
                },
            ],
        }, raw

    def test_reconstructs_ordered_binary_parts_with_collection_cap(self):
        row, expected = self.record()
        calls = []

        def fake_fetch(owner, repo, sha, token=None, max_bytes=None):
            calls.append((repo, max_bytes))
            return {"first": b"abc", "second": b"uvwxyz"}[repo]

        body, status = fetch_full.reconstruct(row, fetcher=fake_fetch)
        self.assertEqual(status, "ok")
        self.assertEqual(body, expected)
        self.assertEqual(calls, [("first", 4), ("second", 4)])

    def test_hash_mismatch_is_not_written_without_opt_in(self):
        row, _ = self.record(expected="0" * 64)

        def fake_fetch(owner, repo, sha, token=None, max_bytes=None):
            return {"first": b"abc", "second": b"uvwxyz"}[repo]

        with tempfile.TemporaryDirectory() as out_dir:
            status = fetch_full.process_row(row, out_dir, fetcher=fake_fetch)
            self.assertEqual(status, "hash_mismatch")
            self.assertFalse(Path(out_dir, "CVE-2099-0005.patch").exists())

            status = fetch_full.process_row(
                row, out_dir, write_mismatches=True, fetcher=fake_fetch
            )
            self.assertEqual(status, "hash_mismatch_written")
            self.assertTrue(Path(out_dir, "CVE-2099-0005.patch").exists())

    def test_existing_bad_cache_is_quarantined_when_refetch_mismatches(self):
        row, _ = self.record(expected="0" * 64)

        def fake_fetch(owner, repo, sha, token=None, max_bytes=None):
            return {"first": b"abc", "second": b"uvwxyz"}[repo]

        with tempfile.TemporaryDirectory() as out_dir:
            destination = Path(out_dir, "CVE-2099-0005.patch")
            destination.write_bytes(b"old bad output")
            status = fetch_full.process_row(row, out_dir, fetcher=fake_fetch)

            self.assertEqual(status, "hash_mismatch")
            self.assertFalse(destination.exists())
            self.assertEqual(
                Path(str(destination) + ".unverified").read_bytes(), b"old bad output"
            )

    def test_reconstructor_rejects_unsafe_cve_filename(self):
        row, _ = self.record()
        row["cve"] = "../../outside"
        with tempfile.TemporaryDirectory() as out_dir:
            self.assertEqual(fetch_full.process_row(row, out_dir), "invalid_cve")

    def test_token_does_not_switch_away_from_dot_patch_url(self):
        requests = []

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, size=-1):
                return b"patch"

        def fake_urlopen(request, timeout=60):
            requests.append(request)
            return Response()

        with mock.patch.object(fetch_full.urllib.request, "urlopen", side_effect=fake_urlopen):
            fetch_full.fetch("org", "repo", "abc", token=None)
            fetch_full.fetch("org", "repo", "abc", token="secret")

        expected_url = "https://github.com/org/repo/commit/abc.patch"
        self.assertEqual([request.full_url for request in requests], [expected_url, expected_url])
        self.assertIsNone(requests[0].get_header("Authorization"))
        self.assertEqual(requests[1].get_header("Authorization"), "Bearer secret")


if __name__ == "__main__":
    unittest.main()
