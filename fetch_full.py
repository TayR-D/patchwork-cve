#!/usr/bin/env python3
"""Reconstruct full fix diffs for the Patchwork dataset.

The dataset ships commit pointers, patch SHA256 hashes and minimal excerpts rather
than wholesale source, so each file stays under its originating repository's licence.
This script re-fetches the complete diffs from GitHub and verifies them against the
recorded hashes.

    python3 fetch_full.py patchwork-cve.jsonl --out patches/

Unauthenticated GitHub tolerates roughly 10 req/s; pass --token for headroom.
"""
import argparse, hashlib, json, os, sys, time
import urllib.request, urllib.error
import concurrent.futures as cf

UA = "patchwork-reconstruct/1.0"

def fetch(owner, repo, sha, token=None, tries=3):
    url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
    headers = {"User-Agent": UA}
    if token:
        url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
        headers |= {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3.diff"}
    delay = 2.0
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                time.sleep(delay); delay *= 4; continue
            return None
        except Exception:
            if attempt == tries - 1: return None
            time.sleep(delay); delay *= 2
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset", help="patchwork-cve.jsonl (or .jsonl.gz)")
    ap.add_argument("--out", default="patches")
    ap.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"))
    ap.add_argument("--threads", type=int, default=6)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    opener = __import__("gzip").open if a.dataset.endswith(".gz") else open
    rows = [json.loads(l) for l in opener(a.dataset, "rt")]
    print(f"{len(rows):,} rows")

    def one(r):
        dest = os.path.join(a.out, f"{r['cve']}.patch")
        if os.path.exists(dest): return "cached"
        body = fetch(r["repo_owner"], r["repo_name"], r["fix_sha"], a.token)
        if body is None: return "failed"
        got = hashlib.sha256(body).hexdigest()
        # note: recorded hashes cover the bytes as fetched at collection time;
        # a mismatch usually means the commit was force-pushed or the repo moved
        status = "ok" if got == r.get("patch_sha256") else "hash_mismatch"
        with open(dest, "wb") as fh: fh.write(body)
        return status

    from collections import Counter
    stats = Counter()
    with cf.ThreadPoolExecutor(a.threads) as ex:
        for i, s in enumerate(ex.map(one, rows)):
            stats[s] += 1
            if (i+1) % 500 == 0: print(f"  [{i+1}/{len(rows)}] {dict(stats)}", flush=True)
    print(f"done: {dict(stats)}")

if __name__ == "__main__":
    main()
