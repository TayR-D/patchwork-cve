#!/usr/bin/env python3
"""Create a deterministic, stratified sample from a Patchwork JSONL release.

This defines the sampling method for future audits.  It does not reconstruct
the unpublished sample used for the v1.0 reliability report.
"""

import argparse
import collections
import gzip
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "out" / "audit_sample.json"
DEFAULT_SEED = "patchwork-audit-v2"


def read_rows(path):
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as source:
        return [json.loads(line) for line in source if line.strip()]


def row_identity(row):
    identity = row.get("cve") or row.get("osv_id")
    if identity:
        return str(identity)
    canonical = json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def stable_rank(row, seed):
    value = f"{seed}\0{row_identity(row)}".encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def allocate(groups, size):
    """Allocate proportionally, with at least one row per label source."""
    total = sum(len(rows) for rows in groups.values())
    if size > total:
        raise ValueError(f"sample size {size} exceeds dataset size {total}")
    if size < len(groups):
        raise ValueError(
            f"sample size {size} cannot cover all {len(groups)} label_source values"
        )
    allocation = {key: 1 for key in groups}
    while sum(allocation.values()) < size:
        candidates = [key for key in groups if allocation[key] < len(groups[key])]
        key = max(
            candidates,
            key=lambda item: (
                size * len(groups[item]) / total - allocation[item],
                len(groups[item]) - allocation[item],
                item,
            ),
        )
        allocation[key] += 1
    return allocation


def ecosystem_round_robin(rows, seed):
    buckets = collections.defaultdict(list)
    for row in rows:
        buckets[str(row.get("ecosystem") or "missing")].append(row)
    for bucket in buckets.values():
        bucket.sort(key=lambda row: stable_rank(row, seed))
    keys = sorted(buckets, key=lambda key: (-len(buckets[key]), key))
    ordered = []
    position = 0
    while True:
        added = False
        for key in keys:
            if position < len(buckets[key]):
                ordered.append(buckets[key][position])
                added = True
        if not added:
            return ordered
        position += 1


def sample_rows(rows, size=100, seed=DEFAULT_SEED):
    groups = collections.defaultdict(list)
    for row in rows:
        groups[str(row.get("label_source") or "missing")].append(row)
    allocation = allocate(groups, size)
    selected = []
    for label_source in sorted(groups):
        ordered = ecosystem_round_robin(groups[label_source], f"{seed}\0{label_source}")
        selected.extend(ordered[: allocation[label_source]])
    return sorted(
        selected,
        key=lambda row: (
            str(row.get("label_source") or "missing"),
            str(row.get("ecosystem") or "missing"),
            row_identity(row),
        ),
    )


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path, help="Patchwork .jsonl or .jsonl.gz release")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--size", type=int, default=100)
    parser.add_argument("--seed", default=DEFAULT_SEED)
    args = parser.parse_args(argv)
    if args.size <= 0:
        parser.error("--size must be positive")

    rows = read_rows(args.dataset)
    selected = sample_rows(rows, args.size, args.seed)
    result = {
        "metadata": {
            "method": (
                "proportional allocation by label_source with a one-row floor; "
                "deterministic SHA-256 ordering round-robin across ecosystems"
            ),
            "seed": args.seed,
            "source_file": args.dataset.name,
            "source_sha256": file_sha256(args.dataset),
            "source_rows": len(rows),
            "sample_rows": len(selected),
            "generator": "pipeline/make_audit_sample.py",
        },
        "rows": selected,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    counts = collections.Counter(row.get("label_source") or "missing" for row in selected)
    print(f"wrote {args.output}: {len(selected)} rows {dict(sorted(counts.items()))}")


if __name__ == "__main__":
    main()
