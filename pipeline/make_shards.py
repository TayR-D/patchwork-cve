#!/usr/bin/env python3
"""Plan Pass A/B shards over the rows that actually have patches.

Shards are stratified by ecosystem and commit-count so that any single shard is a
representative sample -- this matters because cost and quality are re-measured
from whichever shard lands first, and a skewed shard would mis-tune the governor.
"""
import json, os, sys, collections, hashlib

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, "pipeline"))
import batch, fetch_patches
SHARD_ROWS = int(os.environ.get("PW_SHARD_ROWS", "1300"))

def eligible():
    rows = {json.loads(l)["cve"]: json.loads(l) for l in open(os.path.join(R,"out","candidates.jsonl"))}
    status_path = os.path.join(R, "out", "fetch_status.jsonl")
    statuses = fetch_patches.load_latest_status(status_path)
    out = []
    for cve in sorted(rows):
        row = rows[cve]
        if batch.verified_patch_path(row, statuses):
            out.append(row)
    return out

def main():
    os.makedirs(os.path.join(R, "state"), exist_ok=True)
    os.makedirs(os.path.join(R, "out"), exist_ok=True)
    rows = eligible()
    # stratify: round-robin within (ecosystem, multi-commit?) buckets
    buckets = collections.defaultdict(list)
    for r in rows:
        buckets[(r["ecosystem"], r["n_commits"] > 1)].append(r["cve"])
    for k in buckets:
        buckets[k].sort(key=lambda c: hashlib.md5(c.encode()).hexdigest())  # stable shuffle
    order = []
    keys = sorted(buckets, key=lambda k: -len(buckets[k]))
    idx = {k: 0 for k in keys}
    while True:
        added = False
        for k in keys:
            if idx[k] < len(buckets[k]):
                order.append(buckets[k][idx[k]]); idx[k] += 1; added = True
        if not added: break
    n_shards = (len(order) + SHARD_ROWS - 1)//SHARD_ROWS
    assign, shards = {}, []
    for i in range(n_shards):
        chunk = order[i*SHARD_ROWS:(i+1)*SHARD_ROWS]
        sid = f"a{i+1:02d}"
        for c in chunk: assign[c] = sid
        shards.append({"id": sid, "stage": "pass_a", "rows": len(chunk), "status": "pending",
                       "job": None, "model": "gemini-2.5-pro", "thinking": 1024})
    st = {"corpus": len(order), "shard_rows": SHARD_ROWS, "shards": shards, "measured": {}}
    with open(os.path.join(R, "state", "shards.json"), "w") as state_file:
        json.dump(st, state_file, indent=1)
    with open(os.path.join(R, "out", "shard_assign.json"), "w") as assignment_file:
        json.dump(assign, assignment_file)
    print(f"eligible rows : {len(order):,}")
    print(f"shards        : {n_shards} x ~{SHARD_ROWS}")
    print(f"multi-commit  : {sum(1 for r in rows if r['n_commits']>1):,}")
    ec = collections.Counter(r["ecosystem"] for r in rows)
    print("ecosystems    :", dict(ec.most_common(6)))

if __name__ == "__main__":
    main()
