#!/usr/bin/env python3
"""Patchwork session driver -- the daily runbook, in one command.

  python3 scripts/session.py status     what is in flight / done / pending
  python3 scripts/session.py submit N   build+submit up to N shards (governor-gated)
  python3 scripts/session.py harvest    collect finished jobs -> BQ + ledger
  python3 scripts/session.py run        harvest, then submit to keep MAX_INFLIGHT busy

State lives in state/shards.json, mirrored to GCS after every transition, so a
session that dies mid-run resumes rather than restarts.
"""
import json, os, sys, subprocess, datetime
R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, "scripts"))
import batch, ledger, governor

STATE = os.path.join(R, "state", "shards.json")
ASSIGN = os.path.join(R, "out", "shard_assign.json")
# Measured 2026-08-31: Pro and Flash draw from SEPARATE batch throughput pools --
# running Pass B alongside Pass A left Pro at +11.9 rows/min (unchanged). So each
# stage gets its own in-flight budget rather than sharing one.
MAX_INFLIGHT = int(os.environ.get("PW_MAX_INFLIGHT", "3"))
INFLIGHT_BY_STAGE = {"pass_a": int(os.environ.get("PW_INFLIGHT_A", "4")),
                     "pass_b": int(os.environ.get("PW_INFLIGHT_B", "6")),
                     "pass_c": int(os.environ.get("PW_INFLIGHT_C", "4"))}
BUCKET = batch.BUCKET

def load(): return json.load(open(STATE))
def save(st):
    json.dump(st, open(STATE, "w"), indent=1)
    subprocess.run(["gcloud","storage","cp",STATE,f"{BUCKET}/state/shards.json"],
                   capture_output=True, timeout=300)

def rows_for(shard_id):
    st = load()
    sh = next((s for s in st["shards"] if s["id"] == shard_id), None)
    if sh and sh.get("retry_cves") is not None:
        want = set(sh["retry_cves"])
    else:
        assign = json.load(open(ASSIGN))
        src = shard_id
        if shard_id.startswith("b"):      # pass_b mirrors the pass_a shard of the same number
            src = "a" + shard_id[1:]
        want = {c for c, s in assign.items() if s == src and not c.startswith("_b:")}
    return [json.loads(l) for l in open(os.path.join(R,"out","candidates.jsonl"))
            if json.loads(l)["cve"] in want]

def bq_load(table, recs):
    """Load harvested rows into BigQuery (newline JSON, autodetect schema)."""
    if not recs: return
    tmp = os.path.join(R, "out", f"_bq_{table}.jsonl")
    with open(tmp, "w") as fh:
        for r in recs:
            # NOTE: a failed analysis serialises to the STRING "null", not SQL NULL.
            # Kept deliberately: 24 shards load into these tables and a mid-run schema
            # change would drift. Detection happens at export via analysis != 'null'.
            fh.write(json.dumps({**r, "analysis": json.dumps(r.get("analysis"))}) + "\n")
    cp = subprocess.run(["bq","--project_id="+batch.PROJECT,"load","--source_format=NEWLINE_DELIMITED_JSON",
                         "--autodetect","--replace=false",f"patchwork.{table}",tmp],
                        capture_output=True, text=True, timeout=900)
    if cp.returncode != 0:
        print(f"  ! bq load {table} failed: {cp.stderr[:300]}")
    else:
        print(f"  bq: loaded {len(recs)} rows -> patchwork.{table}")

def cmd_status():
    st = load()
    byst = {}
    for s in st["shards"]: byst.setdefault(s["status"], []).append(s["id"])
    print(f"corpus {st['corpus']:,} in {len(st['shards'])} shards")
    for k in ("pending","built","submitted","harvested","failed"):
        if k in byst: print(f"  {k:<10} {len(byst[k]):>3}  {' '.join(byst[k][:14])}")
    print(f"\nledger: {json.dumps(ledger.totals())}")

def cmd_harvest():
    st = load(); changed = False
    for s in st["shards"]:
        if s["status"] != "submitted" or not s.get("job"): continue
        try: j = batch.get_job(s["job"])
        except Exception as e:
            print(f"  {s['id']}: poll failed {str(e)[:150]}"); continue
        state = j.get("state")
        if state == "JOB_STATE_SUCCEEDED":
            recs, errs, cost = batch.harvest(s["id"], s["model"])
            ok = sum(1 for r in recs if r.get("analysis"))
            print(f"  {s['id']}: SUCCEEDED {len(recs)} recs ({ok} parsed), {len(errs)} errs, THB {cost['thb']}")
            bq_load(s["stage"], recs)
            ledger.append(s["stage"], s["model"], s["id"], "batch",
                          cost["tokens_in"], cost["tokens_out"], rows=len(recs))
            s["status"] = "harvested"; s["harvested"] = len(recs); s["parsed"] = ok
            s["thb"] = cost["thb"]; s["errors"] = len(errs)
            # re-measure per-row cost for the governor
            if len(recs):
                st.setdefault("measured", {})[s["stage"]] = round(cost["thb"]/len(recs), 4)
            changed = True
        elif state in ("JOB_STATE_FAILED","JOB_STATE_CANCELLED","JOB_STATE_EXPIRED"):
            err = json.dumps(j.get("error",{}))[:200]
            print(f"  {s['id']}: {state} -- {err}")
            # Vertex batch writes predictions incrementally, so a job that hit the
            # 24h wall (or was cancelled) usually still has real output in GCS.
            # Salvage it -- the alternative is silently discarding paid-for work.
            try:
                recs, errs, cost = batch.harvest(s["id"], s["model"])
                ok = sum(1 for r in recs if r.get("analysis"))
                if recs:
                    bq_load(s["stage"], recs)
                    ledger.append(s["stage"], s["model"], s["id"], "batch",
                                  cost["tokens_in"], cost["tokens_out"], rows=len(recs))
                    print(f"    salvaged {len(recs)} rows ({ok} parsed), THB {cost['thb']}")
                done_cves = {r["cve"] for r in recs if r.get("cve")}
                all_cves = set(rows_for(s["id"]) and [r["cve"] for r in rows_for(s["id"])])
                missing = sorted(all_cves - done_cves)
                s["salvaged"] = len(recs); s["salvaged_thb"] = cost["thb"] if recs else 0
                s["missing_cves"] = missing
                print(f"    missing {len(missing)} rows -> queued for retry")
            except Exception as e:
                print(f"    salvage failed: {type(e).__name__} {str(e)[:150]}")
                s["salvaged"] = 0; s["missing_cves"] = None
            s["status"] = "failed"; s["job_state"] = state; changed = True
        else:
            print(f"  {s['id']}: {state}")
    if changed: save(st); ledger.sync()
    return st

def cmd_submit(n=None):
    st = load()
    gov = governor.project(st, st["corpus"])
    action, notes = governor.decide(gov)
    if action == "HALT":
        print("GOVERNOR HALT:", notes[0]); return
    print(f"governor: {action} (projected THB {gov['projected_total_thb']})")
    todo = []
    for stage, cap in INFLIGHT_BY_STAGE.items():
        infl = sum(1 for s in st["shards"] if s["status"] == "submitted" and s["stage"] == stage)
        free = max(0, cap - infl)
        pend = [s for s in st["shards"] if s["status"] == "pending" and s["stage"] == stage]
        if pend and free == 0:
            print(f"  {stage}: no slots ({infl}/{cap} in flight)")
        todo += pend[:free]
    if not todo:
        return
    for s in todo:
        rows = rows_for(s["id"])
        _, kept, missing = batch.build(rows, s["id"], s["model"], s["thinking"])
        if kept == 0:
            print(f"  {s['id']}: no rows with patches, skipping"); continue
        job = batch.submit(s["id"], s["model"])
        s["status"] = "submitted"; s["job"] = job["name"]; s["built"] = kept; s["missing"] = missing
        s["submitted_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        print(f"  {s['id']}: submitted {kept} rows ({missing} missing patches) job={job['name'].split('/')[-1]}")
        save(st)

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "status": cmd_status()
    elif cmd == "harvest": cmd_harvest(); cmd_status()
    elif cmd == "submit": cmd_submit(int(sys.argv[2]) if len(sys.argv)>2 else 1)
    elif cmd == "run":
        cmd_harvest(); cmd_submit(MAX_INFLIGHT); cmd_status()
    else: print(__doc__)
