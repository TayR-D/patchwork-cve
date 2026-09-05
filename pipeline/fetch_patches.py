#!/usr/bin/env python3
"""Patchwork Phase 1: bulk-fetch fix-commit patches for every candidate CVE.

Free and byte-reproducible from the recorded source commits -- runs before any
credit is spent. Resumable: rows whose status records describe the current byte
format are skipped, so re-running after a crash or a throttling pause continues
where it left off.

Output layout:
  out/patches/{CVE}.patch          concatenated raw .patch bytes
  out/fetch_status.jsonl           status + exact reconstruction provenance
"""
import hashlib, json, os, re, time, random
import urllib.request, urllib.error
import concurrent.futures as cf
from threading import Lock

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATCH_DIR = os.path.join(R, "out", "patches")
STATUS_PATH = os.path.join(R, "out", "fetch_status.jsonl")
MAX_COMMITS = 3            # skip backport storms
MAX_RAW = 512_000          # bytes kept per commit (trim to 32KB happens at request build)
THREADS = 6
PATCH_FORMAT = "github-commit-dot-patch-v1"
PATCH_REPRESENTATION = "github_commit_patch"
PATCH_JOINER = b"\n"
UA = "patchwork-research/0.1 (defensive security dataset; contact via GitHub TayR-D)"
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")

os.makedirs(PATCH_DIR, exist_ok=True)

def patch_url(owner, repo, sha):
    """Return the canonical representation used by collection and reconstruction."""
    return f"https://github.com/{owner}/{repo}/commit/{sha}.patch"

def fetch_one(url, timeout=45, tries=3, token=None):
    """GET with exponential backoff on transient failures / throttling."""
    headers = {"User-Agent": UA}
    if token:
        # Authentication changes only the request header, never the representation.
        # In particular, do not substitute the GitHub API's raw diff response.
        headers["Authorization"] = f"Bearer {token}"
    delay = 2.0
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(MAX_RAW + 1), None
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):           # throttled: back off hard, then retry
                time.sleep(delay + random.random() * 2); delay *= 4
                continue
            return None, f"http{e.code}"
        except Exception as e:
            if attempt == tries - 1:
                return None, type(e).__name__
            time.sleep(delay); delay *= 2
    return None, "throttled"

def status_has_reconstruction_provenance(status):
    """Whether a successful status row unambiguously describes its patch bytes."""
    commits = status.get("patch_commits")
    return (
        status.get("status") in ("ok", "cached")
        and status.get("patch_format") == PATCH_FORMAT
        and isinstance(commits, list)
        and bool(commits)
        and status.get("n_fetched") == status.get("n_commits") == len(commits)
        and all(commit.get("included") is True and commit.get("fetch_status") == "ok"
                for commit in commits)
    )

def file_sha256(path):
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def candidate_fingerprint(candidate, patch_sha256):
    """Fingerprint all advisory/commit input plus the verified collected patch."""
    if not isinstance(candidate, dict) or not patch_sha256:
        return None
    source = {
        key: value for key, value in candidate.items()
        if key not in {"patch_sha256", "candidate_fingerprint"}
    }
    encoded = json.dumps(
        {"candidate": source, "patch_sha256": patch_sha256},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()

def status_matches_patch(status, candidate, patch_dir=None):
    """Resume only when bytes and ordered source commits still match the candidate."""
    if not status_has_reconstruction_provenance(status) or not isinstance(candidate, dict):
        return False
    cve = candidate.get("cve")
    if (not isinstance(cve, str) or CVE_RE.fullmatch(cve) is None
            or status.get("cve") != cve):
        return False
    expected_commits = candidate.get("commits") or []
    recorded_commits = status["patch_commits"]
    try:
        candidate_count = int(candidate["n_commits"])
    except (KeyError, TypeError, ValueError):
        return False
    if candidate_count != len(expected_commits) or len(expected_commits) != len(recorded_commits):
        return False
    for expected_commit, recorded_commit in zip(expected_commits, recorded_commits):
        expected_identity = tuple(
            str(expected_commit.get(field) or "").lower()
            for field in ("owner", "repo", "sha")
        )
        recorded_identity = tuple(
            str(recorded_commit.get(field) or "").lower()
            for field in ("owner", "repo", "sha")
        )
        if not all(expected_identity) or recorded_identity != expected_identity:
            return False
    expected = status.get("patch_sha256")
    if not expected:
        return False
    path = os.path.join(patch_dir or PATCH_DIR, f"{cve}.patch")
    return file_sha256(path) == expected


def repair_trailing_status_fragment(path=STATUS_PATH):
    """Remove only an incomplete final append-log fragment after preserving it.

    A process kill can interrupt the final status write.  Without this repair, the
    next append would concatenate a new JSON object onto that fragment and make both
    records unreadable.  Complete JSON without a final newline is retained.
    """
    path = os.fspath(path)
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return None
    with open(path, "rb") as status_file:
        raw = status_file.read()
    if raw.endswith(b"\n"):
        return None
    boundary = raw.rfind(b"\n") + 1
    fragment = raw[boundary:]
    try:
        json.loads(fragment.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        corrupt_path = path + ".corrupt"
        suffix = 1
        while os.path.exists(corrupt_path):
            corrupt_path = f"{path}.corrupt.{suffix}"
            suffix += 1
        with open(corrupt_path, "wb") as corrupt_file:
            corrupt_file.write(fragment)
        with open(path, "r+b") as status_file:
            status_file.truncate(boundary)
        return corrupt_path
    with open(path, "ab") as status_file:
        status_file.write(b"\n")
    return None


def load_latest_status(path=STATUS_PATH):
    """Read a status append log strictly, with last valid row per CVE winning."""
    path = os.fspath(path)
    latest = {}
    if not os.path.exists(path):
        return latest
    with open(path, encoding="utf-8") as status_file:
        for line_number, line in enumerate(status_file, 1):
            if not line.strip():
                continue
            try:
                status = json.loads(line)
            except json.JSONDecodeError as error:
                raise RuntimeError(
                    f"invalid fetch status JSON on line {line_number}: {error.msg}"
                ) from error
            cve = status.get("cve")
            if isinstance(cve, str):
                latest[cve] = status
    return latest

def quarantine_incomplete_patch(path):
    """Keep an old derived patch for inspection without making it pipeline-eligible."""
    if not os.path.exists(path):
        return None
    target = path + ".unverified"
    suffix = 1
    while os.path.exists(target):
        target = f"{path}.unverified.{suffix}"
        suffix += 1
    os.replace(path, target)
    return target

def process(row):
    cve = row["cve"]
    if not isinstance(cve, str) or CVE_RE.fullmatch(cve) is None:
        return {"cve": cve, "status": "invalid_cve"}
    dest = os.path.join(PATCH_DIR, f"{cve}.patch")
    commits = row["commits"][:MAX_COMMITS]
    if row["n_commits"] > MAX_COMMITS:
        return {"cve": cve, "status": "skipped_too_many_commits", "n_commits": row["n_commits"]}
    parts, errs, descriptors = [], [], []
    t0 = time.time()
    token = os.environ.get("GITHUB_TOKEN")
    for position, c in enumerate(commits):
        url = patch_url(c["owner"], c["repo"], c["sha"])
        descriptor = {
            "position": position,
            "owner": c["owner"],
            "repo": c["repo"],
            "sha": c["sha"],
            "ref_type": c.get("ref_type"),
            "source_url": url,
            "representation": PATCH_REPRESENTATION,
            "max_bytes": MAX_RAW,
        }
        body, err = fetch_one(url, token=token)
        if body == b"" and err is None:
            err = "empty_response"
        if err:
            errs.append(err)
            descriptor.update({
                "included": False,
                "fetch_status": "error",
                "fetch_error": err,
            })
            descriptors.append(descriptor)
            continue
        bytes_observed = len(body)
        truncated = bytes_observed > MAX_RAW
        kept = body[:MAX_RAW]
        parts.append(kept)
        descriptor.update({
            "included": True,
            "fetch_status": "ok",
            # When truncated this is a lower bound, because fetch_one deliberately
            # reads only MAX_RAW + 1 bytes to detect overflow.
            "response_bytes_observed": bytes_observed,
            "response_size_is_lower_bound": truncated,
            "bytes_kept": len(kept),
            "truncated": truncated,
            "collected_sha256": hashlib.sha256(kept).hexdigest(),
        })
        descriptors.append(descriptor)
    if not parts:
        quarantined = quarantine_incomplete_patch(dest)
        return {
            "cve": cve,
            "status": "failed",
            "errors": errs,
            "patch_format": PATCH_FORMAT,
            "patch_representation": PATCH_REPRESENTATION,
            "patch_joiner": "LF",
            "patch_max_bytes_per_commit": MAX_RAW,
            "patch_commits": descriptors,
            "quarantined_patch": quarantined,
            "secs": round(time.time() - t0, 2),
        }
    raw = PATCH_JOINER.join(parts)
    quarantined = None
    if errs:
        # Other stages treat any canonical *.patch file as eligible. Never leave
        # a partial multi-commit result at that path.
        quarantined = quarantine_incomplete_patch(dest)
    else:
        tmp = dest + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(raw)
        os.replace(tmp, dest)
    return {
        "cve": cve,
        # Partial-response metadata is kept for diagnostics, but no canonical
        # patch is written and the row must not enter a release. A later run retries it.
        "status": "partial" if errs else "ok",
        "bytes": len(raw),
        "patch_sha256": hashlib.sha256(raw).hexdigest(),
        "n_fetched": len(parts),
        "n_commits": len(commits),
        "patch_format": PATCH_FORMAT,
        "patch_representation": PATCH_REPRESENTATION,
        "patch_joiner": "LF",
        "patch_max_bytes_per_commit": MAX_RAW,
        "patch_truncated": any(d.get("truncated", False) for d in descriptors),
        "patch_partial_fetch": bool(errs),
        "patch_complete": not errs and not any(d.get("truncated", False) for d in descriptors),
        "patch_commits": descriptors,
        "partial_errors": errs or None,
        "quarantined_patch": quarantined,
        "secs": round(time.time() - t0, 2),
    }

def main():
    rows = [json.loads(l) for l in open(os.path.join(R, "out", "candidates.jsonl"))]
    done_cves = set()
    corrupt = repair_trailing_status_fragment()
    if corrupt:
        print(f"preserved incomplete status fragment at {corrupt}", flush=True)
    latest_status = load_latest_status()
    rows_by_cve = {row["cve"]: row for row in rows}
    for cve, status in latest_status.items():
        # Legacy successful rows do not identify which commits failed, how bytes
        # were truncated, or whether text decoding changed the bytes. Re-fetch them
        # once into the versioned, reproducible format. Partial/failed rows also retry.
        candidate = rows_by_cve.get(cve)
        still_too_many = (
            status.get("status") == "skipped_too_many_commits"
            and isinstance(candidate, dict)
            and candidate.get("n_commits", 0) > MAX_COMMITS
        )
        if status_matches_patch(status, candidate) or still_too_many:
            done_cves.add(cve)
    todo = [r for r in rows if r["cve"] not in done_cves]
    print(f"candidates={len(rows)} already-done={len(done_cves)} todo={len(todo)}", flush=True)
    lock = Lock()
    stats = {"ok": 0, "partial": 0, "failed": 0, "skipped_too_many_commits": 0}
    t0 = time.time()
    with open(STATUS_PATH, "a") as out, cf.ThreadPoolExecutor(THREADS) as ex:
        for i, res in enumerate(ex.map(process, todo)):
            with lock:
                out.write(json.dumps(res) + "\n")
                stats[res["status"]] = stats.get(res["status"], 0) + 1
                if (i + 1) % 500 == 0:
                    out.flush()
                    rate = (i + 1) / (time.time() - t0)
                    eta = (len(todo) - i - 1) / rate / 60
                    print(f"[{i+1}/{len(todo)}] {stats} {rate:.1f}/s eta {eta:.0f}m", flush=True)
    print(f"DONE in {(time.time()-t0)/60:.1f}m: {stats}", flush=True)

if __name__ == "__main__":
    main()
