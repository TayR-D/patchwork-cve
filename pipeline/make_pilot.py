#!/usr/bin/env python3
"""Build the 200-row stratified pilot shard (Phase 3 gate).

The smoke test measured mechanics on 5 unrepresentative old CVEs. This sample is
stratified across ecosystem x commit-count x advisory-CWE-present x era so the
cost and quality numbers it produces actually generalise to the corpus.
"""
import json, os, sys, collections, hashlib, random

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
N = int(os.environ.get("PW_PILOT_N", "200"))

def era(cve):
    y = int(cve.split("-")[1])
    return "old" if y < 2018 else ("mid" if y < 2023 else "new")

def main():
    rows = [json.loads(l) for l in open(os.path.join(R,"out","candidates.jsonl"))]
    have = {f[:-6] for f in os.listdir(os.path.join(R,"out","patches")) if f.endswith(".patch")}
    pool = [r for r in rows if r["cve"] in have]
    print(f"pool with patches: {len(pool):,}")
    strata = collections.defaultdict(list)
    for r in pool:
        strata[(r["ecosystem"], r["n_commits"] > 1, bool(r.get("cwe_ids")), era(r["cve"]))].append(r)
    # proportional allocation with a floor of 1 per non-empty stratum
    keys = sorted(strata, key=lambda k: -len(strata[k]))
    total = len(pool)
    alloc = {k: max(1, round(N * len(strata[k]) / total)) for k in keys}
    while sum(alloc.values()) > N:
        k = max(alloc, key=lambda k: alloc[k]); alloc[k] -= 1
        if alloc[k] == 0: del alloc[k]
    picked = []
    for k, n in alloc.items():
        g = sorted(strata[k], key=lambda r: hashlib.md5(r["cve"].encode()).hexdigest())
        picked.extend(g[:n])
    print(f"strata: {len(alloc)}  picked: {len(picked)}")
    ec = collections.Counter(r["ecosystem"] for r in picked)
    er = collections.Counter(era(r["cve"]) for r in picked)
    print("  ecosystems:", dict(ec.most_common(8)))
    print("  eras      :", dict(er))
    print("  multi-commit:", sum(1 for r in picked if r["n_commits"]>1))
    print("  with adv CWE:", sum(1 for r in picked if r.get("cwe_ids")))
    json.dump([r["cve"] for r in picked], open(os.path.join(R,"out","pilot200_cves.json"),"w"))
    return picked

if __name__ == "__main__":
    main()
