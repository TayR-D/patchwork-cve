#!/usr/bin/env python3
"""Reconstruct the exact collected fix-patch bytes for Patchwork records.

Current records carry an ordered descriptor for every attempted fix commit, the
per-commit byte cap, the join format, and the final SHA256. That lets this script
reproduce the bytes used for analysis even when a CVE has several commits or a
large commit was truncated during collection.

Legacy rows containing only ``repo_owner``, ``repo_name`` and ``fix_sha`` remain
supported for single, untruncated commits. Their hash check will intentionally
fail instead of writing an incorrect file when the old row represented a
multi-commit or truncated patch.

    python3 fetch_full.py patchwork-cve.jsonl --out patches/

Authentication only adds an HTTP header to the same github.com ``.patch`` URL;
it never switches to the GitHub API's byte-incompatible raw-diff representation.
"""
import argparse
import concurrent.futures as cf
import gzip
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from collections import Counter

UA = "patchwork-reconstruct/1.1"
PATCH_FORMAT = "github-commit-dot-patch-v1"
PATCH_REPRESENTATION = "github_commit_patch"
DEFAULT_MAX_BYTES = 512_000
PATCH_JOINERS = {"LF": b"\n"}
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")


def patch_url(owner, repo, sha):
    """Return the canonical patch URL used in both authentication modes."""
    return f"https://github.com/{owner}/{repo}/commit/{sha}.patch"


def fetch(owner, repo, sha, token=None, tries=3, max_bytes=None):
    """Fetch GitHub's commit ``.patch`` representation with retry/backoff.

    ``max_bytes`` mirrors collection: one extra byte is read solely to detect
    whether the response exceeded the cap.
    """
    url = patch_url(owner, repo, sha)
    headers = {"User-Agent": UA}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    delay = 2.0
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as response:
                return response.read(max_bytes + 1 if max_bytes is not None else -1)
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429):
                time.sleep(delay)
                delay *= 4
                continue
            return None
        except Exception:
            if attempt == tries - 1:
                return None
            time.sleep(delay)
            delay *= 2
    return None


def _as_bool(value):
    if isinstance(value, str):
        return value.lower() == "true"
    return bool(value)


def _ordered_descriptors(row):
    if "patch_commits" not in row or row.get("patch_commits") is None:
        return None, "legacy"
    descriptors = row.get("patch_commits")
    if isinstance(descriptors, str):
        try:
            descriptors = json.loads(descriptors)
        except json.JSONDecodeError:
            return None, "invalid_provenance"
    if not isinstance(descriptors, list) or not descriptors:
        return None, "invalid_provenance"
    if any(not isinstance(descriptor, dict) for descriptor in descriptors):
        return None, "invalid_provenance"

    # Arrays are ordered, but the explicit position survives storage systems that
    # may not preserve repeated-field order. Reject ambiguous positions.
    positions = [descriptor.get("position") for descriptor in descriptors]
    if all(isinstance(position, int) or (isinstance(position, str) and position.isdigit())
           for position in positions):
        numeric_positions = [int(position) for position in positions]
        if len(set(numeric_positions)) != len(numeric_positions):
            return None, "invalid_provenance"
        descriptors = [descriptor for _, descriptor in sorted(
            zip(numeric_positions, descriptors), key=lambda item: item[0]
        )]
    elif any(position is not None for position in positions):
        return None, "invalid_provenance"
    return descriptors, None


def reconstruct(row, token=None, fetcher=fetch):
    """Return ``(bytes, status)`` for one row without writing to disk."""
    descriptors, descriptor_status = _ordered_descriptors(row)
    if descriptor_status == "legacy":
        required = (row.get("repo_owner"), row.get("repo_name"), row.get("fix_sha"))
        if not all(required):
            return None, "invalid_provenance"
        body = fetcher(*required, token=token, max_bytes=None)
        return (body, "ok") if body is not None else (None, "failed")
    if descriptor_status:
        return None, descriptor_status

    if row.get("patch_format") != PATCH_FORMAT:
        return None, "unsupported_patch_format"
    if row.get("patch_representation", PATCH_REPRESENTATION) != PATCH_REPRESENTATION:
        return None, "unsupported_patch_format"
    joiner = PATCH_JOINERS.get(row.get("patch_joiner", "LF"))
    if joiner is None:
        return None, "unsupported_patch_format"

    try:
        default_cap = int(row.get("patch_max_bytes_per_commit", DEFAULT_MAX_BYTES))
    except (TypeError, ValueError):
        return None, "invalid_provenance"
    if default_cap < 0:
        return None, "invalid_provenance"

    parts = []
    for descriptor in descriptors:
        if not _as_bool(descriptor.get("included", True)):
            # Collection omitted commits that failed to fetch. Reproduction must
            # omit the same commit even if it has since become available.
            continue
        if descriptor.get("representation", PATCH_REPRESENTATION) != PATCH_REPRESENTATION:
            return None, "unsupported_patch_format"
        required = (
            descriptor.get("owner"),
            descriptor.get("repo"),
            descriptor.get("sha"),
        )
        if not all(required):
            return None, "invalid_provenance"
        try:
            cap = int(descriptor.get("max_bytes", default_cap))
        except (TypeError, ValueError):
            return None, "invalid_provenance"
        if cap < 0:
            return None, "invalid_provenance"
        body = fetcher(*required, token=token, max_bytes=cap)
        if body is None:
            return None, "failed"
        part = body[:cap]

        expected_bytes = descriptor.get("bytes_kept")
        if expected_bytes is not None:
            try:
                if len(part) != int(expected_bytes):
                    return None, "commit_hash_mismatch"
            except (TypeError, ValueError):
                return None, "invalid_provenance"
        expected_part_hash = descriptor.get("collected_sha256")
        if expected_part_hash and hashlib.sha256(part).hexdigest() != expected_part_hash:
            return None, "commit_hash_mismatch"
        parts.append(part)

    if not parts:
        return None, "invalid_provenance"
    return joiner.join(parts), "ok"


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_atomic(path, body):
    tmp = path + ".tmp"
    try:
        with open(tmp, "wb") as destination:
            destination.write(body)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _quarantine_unverified(path):
    """Move an existing bad cache entry aside without deleting user-visible data."""
    target = path + ".unverified"
    suffix = 1
    while os.path.exists(target):
        target = f"{path}.unverified.{suffix}"
        suffix += 1
    os.replace(path, target)
    return target


def process_row(row, out_dir, token=None, write_mismatches=False, fetcher=fetch):
    """Reconstruct one row, writing only verified bytes by default."""
    cve = row.get("cve")
    if not isinstance(cve, str) or CVE_RE.fullmatch(cve) is None:
        return "invalid_cve"
    dest = os.path.join(out_dir, f"{cve}.patch")
    expected = row.get("patch_sha256")
    if os.path.exists(dest):
        if expected and _sha256_file(dest) == expected:
            return "cached"
        if not expected:
            return "cached_unverified"
        # A prior version wrote mismatches to the canonical destination. Preserve
        # such a file for inspection, but do not let it masquerade as valid output.
        _quarantine_unverified(dest)

    body, status = reconstruct(row, token=token, fetcher=fetcher)
    if body is None:
        return status
    got = hashlib.sha256(body).hexdigest()
    if expected and got != expected:
        if not write_mismatches:
            return "hash_mismatch"
        _write_atomic(dest, body)
        return "hash_mismatch_written"
    _write_atomic(dest, body)
    return "ok" if expected else "ok_unverified"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", help="patchwork-cve.jsonl (or .jsonl.gz)")
    parser.add_argument("--out", default="patches")
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"))
    parser.add_argument("--threads", type=int, default=6)
    parser.add_argument(
        "--write-mismatches",
        action="store_true",
        help="write reconstructed bytes even when their SHA256 differs (unsafe; off by default)",
    )
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)
    opener = gzip.open if args.dataset.endswith(".gz") else open
    with opener(args.dataset, "rt") as source:
        rows = [json.loads(line) for line in source]
    print(f"{len(rows):,} rows")

    stats = Counter()
    with cf.ThreadPoolExecutor(args.threads) as executor:
        results = executor.map(
            lambda row: process_row(
                row,
                args.out,
                token=args.token,
                write_mismatches=args.write_mismatches,
            ),
            rows,
        )
        for index, status in enumerate(results, 1):
            stats[status] += 1
            if index % 500 == 0:
                print(f"  [{index}/{len(rows)}] {dict(stats)}", flush=True)
    print(f"done: {dict(stats)}")


if __name__ == "__main__":
    main()
