#!/usr/bin/env python3
"""Patchwork spend ledger: self-accounted from usageMetadata.

Cloud Billing data lags ~24h, so the authoritative in-run spend number is this
ledger, computed from tokens actually returned by every API call at verified
SKU rates. Append-only JSONL locally, mirrored to GCS, loaded into BigQuery.
"""
import json, os, sys, subprocess, datetime

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(R, "out", "ledger.jsonl")
BUCKET = os.environ.get("PW_BUCKET", "gs://patchwork-cve-a1adb1-forge")
THB_PER_USD = 34.5
RATES = {"gemini-2.5-pro":   {"batch": (0.625, 5.00), "ondemand": (1.25, 10.00)},
         "gemini-2.5-flash": {"batch": (0.15,  1.25), "ondemand": (0.30,  2.50)},
         "gemini-2.5-flash-lite": {"batch": (0.05, 0.20), "ondemand": (0.10, 0.40)}}

def cost(model, mode, tin, tout):
    ri, ro = RATES[model][mode]
    usd = (tin*ri + tout*ro)/1e6
    return round(usd, 6), round(usd*THB_PER_USD, 4)

def append(stage, model, shard, mode, tin, tout, rows=0, note=""):
    usd, thb = cost(model, mode, tin, tout)
    rec = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "stage": stage, "model": model, "shard": shard, "mode": mode,
           "rows": rows, "tokens_in": tin, "tokens_out": tout,
           "usd": usd, "thb": thb, "note": note}
    with open(LEDGER, "a") as fh:
        fh.write(json.dumps(rec) + "\n")
    return rec

def totals():
    if not os.path.exists(LEDGER):
        return {"calls": 0, "rows": 0, "tokens_in": 0, "tokens_out": 0, "usd": 0.0, "thb": 0.0}
    t = {"calls": 0, "rows": 0, "tokens_in": 0, "tokens_out": 0, "usd": 0.0, "thb": 0.0}
    for l in open(LEDGER):
        d = json.loads(l)
        t["calls"] += 1; t["rows"] += d.get("rows", 0)
        t["tokens_in"] += d["tokens_in"]; t["tokens_out"] += d["tokens_out"]
        t["usd"] += d["usd"]; t["thb"] += d["thb"]
    t["usd"] = round(t["usd"], 4); t["thb"] = round(t["thb"], 2)
    return t

def sync():
    """Regenerate spend_todate.json (dashboard input) and mirror ledger to GCS."""
    t = totals()
    json.dump(t, open(os.path.join(R, "out", "spend_todate.json"), "w"), indent=1)
    if os.path.exists(LEDGER):
        subprocess.run(["gcloud","storage","cp",LEDGER,f"{BUCKET}/state/ledger.jsonl"],
                       capture_output=True, timeout=300)
    return t

def seed_from_pilots():
    """One-time: fold day-1 on-demand pilot spend into the ledger."""
    if os.path.exists(LEDGER):
        print("ledger exists; refusing to double-seed"); return totals()
    sp = json.load(open(os.path.join(R, "out", "spend_todate.json")))
    # day-1 pilots ran on-demand; recorded as a single reconciling entry
    rec = {"ts": "2026-08-30T00:00:00+00:00", "stage": "day1-pilot", "model": "gemini-2.5-pro",
           "shard": "pilot", "mode": "ondemand", "rows": 52,
           "tokens_in": sp["tokens_in"], "tokens_out": sp["tokens_out"],
           "usd": sp["usd"], "thb": sp["thb"], "note": "day-1 on-demand pilots (pro+flash mixed)"}
    with open(LEDGER, "w") as fh:
        fh.write(json.dumps(rec) + "\n")
    return totals()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "seed":
        print(json.dumps(seed_from_pilots(), indent=1))
    else:
        print(json.dumps(sync(), indent=1))
