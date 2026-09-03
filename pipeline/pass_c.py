#!/usr/bin/env python3
"""Pass C driver: build, submit and harvest adjudication shards.

Runs after score_agreement.py has produced out/adjudicate_cves.json. Uses 4-6
shards in flight (not the maximum) so shards complete progressively -- Pro
throughput is globally capped, so extra concurrency only spreads it thinner.
"""
import json, os, sys, subprocess, collections, datetime
R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, "scripts"))
import batch, ledger, adjudicate, session

SHARD_ROWS = int(os.environ.get("PW_C_SHARD_ROWS", "700"))
INFLIGHT   = int(os.environ.get("PW_INFLIGHT_C", "4"))
STATE      = os.path.join(R, "state", "pass_c.json")

CACHE = os.path.join(R, "out", "pass_c_analyses.json")

def load_analyses():
    """Pro+Flash analyses for the adjudication candidates only.

    Cached to disk: the loop calls this every cycle, and re-pulling 33k rows from
    BigQuery each time is slow and pointless -- the analyses are immutable now that
    Pass A and B are complete.
    """
    if os.path.exists(CACHE):
        d = json.load(open(CACHE))
        return d["pro"], d["flash"]
    import score_agreement as sa
    want = set(json.load(open(f"{R}/out/adjudicate_cves.json")))
    pro = {k: v for k, v in sa.load_pass("pass_a").items() if k in want}
    fla = {k: v for k, v in sa.load_pass("pass_b").items() if k in want}
    json.dump({"pro": pro, "flash": fla}, open(CACHE, "w"))
    print(f"  cached {len(pro)} pro / {len(fla)} flash analyses -> {CACHE}")
    return pro, fla

def plan():
    cves = json.load(open(f"{R}/out/adjudicate_cves.json"))
    shards = []
    for i in range(0, len(cves), SHARD_ROWS):
        shards.append({"id": f"c{i//SHARD_ROWS+1:02d}", "stage": "pass_c",
                       "cves": cves[i:i+SHARD_ROWS], "status": "pending", "job": None,
                       "model": "gemini-2.5-pro", "thinking": 1024})
    st = {"total": len(cves), "shards": shards}
    json.dump(st, open(STATE, "w"), indent=1)
    print(f"pass C: {len(cves):,} candidates -> {len(shards)} shards of {SHARD_ROWS}")
    return st

def build_shard(sh, rows, pro, fla):
    local = os.path.join(R, "out", "batch_in", f"{sh['id']}.jsonl")
    os.makedirs(os.path.dirname(local), exist_ok=True)
    kept, slots = [], {}
    with open(local, "w") as fh:
        for cve in sh["cves"]:
            row = rows.get(cve); pa = (pro.get(cve) or {}).get("analysis")
            fb = (fla.get(cve) or {}).get("analysis")
            pf = os.path.join(R, "out", "patches", f"{cve}.patch")
            if not (row and pa and fb and os.path.exists(pf)): continue
            body, sl = adjudicate.build_adj_request(
                row, pa, fb, open(pf, encoding="utf-8", errors="replace").read(),
                thinking=sh["thinking"])
            fh.write(json.dumps({"request": body}) + "\n")
            kept.append(cve); slots[cve] = sl
    batch.gs("cp", local, f"{batch.BUCKET}/batch_in/{sh['id']}.jsonl")
    json.dump({"rows": kept, "slots": slots},
              open(os.path.join(R, "out", "batch_in", f"{sh['id']}.slots.json"), "w"))
    return len(kept)

def run():
    st = json.load(open(STATE)) if os.path.exists(STATE) else plan()
    rows = {json.loads(l)["cve"]: json.loads(l) for l in open(f"{R}/out/candidates.jsonl")}
    pro, fla = load_analyses()
    # harvest finished
    for sh in st["shards"]:
        if sh["status"] != "submitted": continue
        j = batch.get_job(sh["job"]); state = j.get("state")
        if state == "JOB_STATE_SUCCEEDED":
            recs, errs, cost = batch.harvest(sh["id"], sh["model"])
            ok = sum(1 for r in recs if r.get("analysis"))
            print(f"  {sh['id']}: SUCCEEDED {len(recs)} recs ({ok} parsed), THB {cost['thb']}")
            session.bq_load("pass_c", recs)
            ledger.append("pass_c", sh["model"], sh["id"], "batch",
                          cost["tokens_in"], cost["tokens_out"], rows=len(recs))
            sh["status"] = "harvested"; sh["thb"] = cost["thb"]
        elif state in ("JOB_STATE_FAILED","JOB_STATE_CANCELLED","JOB_STATE_EXPIRED"):
            print(f"  {sh['id']}: {state}"); sh["status"] = "failed"
        else:
            print(f"  {sh['id']}: {state}")
    # submit up to INFLIGHT
    infl = sum(1 for s in st["shards"] if s["status"] == "submitted")
    for sh in [s for s in st["shards"] if s["status"] == "pending"][:max(0, INFLIGHT - infl)]:
        n = build_shard(sh, rows, pro, fla)
        if n == 0:
            sh["status"] = "empty"; continue
        j = batch.submit(sh["id"], sh["model"])
        sh["status"] = "submitted"; sh["job"] = j["name"]; sh["built"] = n
        print(f"  {sh['id']}: submitted {n} rows")
    json.dump(st, open(STATE, "w"), indent=1)
    ledger.sync()
    c = collections.Counter(s["status"] for s in st["shards"])
    print(f"  pass C status: {dict(c)}")
    return st

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "plan": plan()
    else: run()
