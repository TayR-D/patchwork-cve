#!/usr/bin/env python3
"""Plan Pass A/B shards over the rows that actually have patches.

Shards are stratified by ecosystem and commit-count so that any single shard is a
representative sample -- this matters because cost and quality are re-measured
from whichever shard lands first, and a skewed shard would mis-tune the governor.
"""
import json, os, sys, collections, hashlib

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHARD_ROWS = int(os.environ.get("PW_SHARD_ROWS", "1300"))

def eligible():
    rows = {json.loads(l)["cve"]: json.loads(l) for l in open(os.path.join(R,"out","candidates.jsonl"))}
    pdir = os.path.join(R, "out", "patches")
    have = {f[:-6] for f in os.listdir(pdir) if f.endswith(".patch")}
    out = []
    for cve in sorted(have):
        r = rows.get(cve)
        if r: out.append(r)
    return out

def main():
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
    json.dump(st, open(os.path.join(R,"state","shards.json"),"w"), indent=1)
    json.dump(assign, open(os.path.join(R,"out","shard_assign.json"),"w"))
    print(f"eligible rows : {len(order):,}")
    print(f"shards        : {n_shards} x ~{SHARD_ROWS}")
    print(f"multi-commit  : {sum(1 for r in rows if r['n_commits']>1):,}")
    ec = collections.Counter(r["ecosystem"] for r in rows)
    print("ecosystems    :", dict(ec.most_common(6)))

if __name__ == "__main__":
    main()
