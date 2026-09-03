#!/usr/bin/env python3
"""Patchwork Phase 1: bulk-fetch fix-commit patches for every candidate CVE.

Free and deterministic -- runs before any credit is spent. Resumable: rows whose
patch files already exist locally are skipped, so re-running after a crash or a
throttling pause continues where it left off.

Output layout:
  out/patches/{CVE}.patch          concatenated raw patches (multi-commit joined)
  out/fetch_status.jsonl           one row per CVE: status + sizes + timing
"""
import json, os, re, sys, time, gzip, random
import urllib.request, urllib.error
import concurrent.futures as cf
from threading import Lock

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATCH_DIR = os.path.join(R, "out", "patches")
STATUS_PATH = os.path.join(R, "out", "fetch_status.jsonl")
MAX_COMMITS = 3            # skip backport storms
MAX_RAW = 512_000          # bytes kept per CVE (trim to 32KB happens at request build)
THREADS = 6
UA = {"User-Agent": "patchwork-research/0.1 (defensive security dataset; contact via GitHub TayR-D)"}

os.makedirs(PATCH_DIR, exist_ok=True)

def fetch_one(url, timeout=45, tries=3):
    """GET with exponential backoff on transient failures / throttling."""
    delay = 2.0
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers=UA)
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

def process(row):
    cve = row["cve"]
    dest = os.path.join(PATCH_DIR, f"{cve}.patch")
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        return {"cve": cve, "status": "cached"}
    commits = row["commits"][:MAX_COMMITS]
    if row["n_commits"] > MAX_COMMITS:
        return {"cve": cve, "status": "skipped_too_many_commits", "n_commits": row["n_commits"]}
    parts, errs = [], []
    t0 = time.time()
    for c in commits:
        url = f"https://github.com/{c['owner']}/{c['repo']}/commit/{c['sha']}.patch"
        body, err = fetch_one(url)
        if err:
            errs.append(err)
            continue
        if len(body) > MAX_RAW:
            body = body[:MAX_RAW]          # keep head; trim stage handles the rest
        parts.append(body.decode("utf-8", "replace"))
    if not parts:
        return {"cve": cve, "status": "failed", "errors": errs, "secs": round(time.time() - t0, 2)}
    text = "\n".join(parts)
    tmp = dest + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(text)
    os.replace(tmp, dest)
    return {"cve": cve, "status": "ok", "bytes": len(text),
            "n_fetched": len(parts), "n_commits": len(commits),
            "partial_errors": errs or None, "secs": round(time.time() - t0, 2)}

def main():
    rows = [json.loads(l) for l in open(os.path.join(R, "out", "candidates.jsonl"))]
    done_cves = set()
    if os.path.exists(STATUS_PATH):
        for l in open(STATUS_PATH):
            try:
                d = json.loads(l)
                if d["status"] in ("ok", "cached", "skipped_too_many_commits"):
                    done_cves.add(d["cve"])
            except Exception:
                pass
    todo = [r for r in rows if r["cve"] not in done_cves]
    print(f"candidates={len(rows)} already-done={len(done_cves)} todo={len(todo)}", flush=True)
    lock = Lock()
    stats = {"ok": 0, "cached": 0, "failed": 0, "skipped_too_many_commits": 0}
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
