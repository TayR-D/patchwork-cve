#!/usr/bin/env python3
"""Patchwork budget governor -- run at the start of every session.

Projects total spend from measured actuals and decides whether to proceed, cut
scope, or stretch. Overshoot and underspend are both failures: the credit expires
either way, so unused budget is wasted budget.
"""
import json, os, sys, datetime

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, "pipeline"))
import ledger

TARGET_THB   = 9400
HARDSTOP_THB = 9900
FLOOR_THB    = 8400      # below this we are wasting credit
EXPIRY       = datetime.date(2026, 9, 17)

# fallback per-row costs (THB) until measured from a real harvest
PRIOR = {"pass_a": 0.395, "pass_b": 0.077, "pass_c": 0.52}

def load_state():
    p = os.path.join(R, "state", "shards.json")
    return json.load(open(p)) if os.path.exists(p) else {"shards": [], "measured": {}}

def measured_cost(state, stage):
    m = state.get("measured", {}).get(stage)
    return m if m else PRIOR[stage]

def project(state, corpus_rows, conflict_rate=None):
    spent = ledger.totals()["thb"]
    # measured adjudication rate from the pilot beats the 0.21 prior
    if conflict_rate is None:
        conflict_rate = state.get("adj_rate", 0.21)
    done = {s: 0 for s in ("pass_a","pass_b","pass_c")}
    # rows already analysed in the pilot shards are not re-run
    pilot = len(state.get("pilot_done", []))
    done["pass_a"] += pilot; done["pass_b"] += pilot
    for sh in state.get("shards", []):
        if sh.get("status") == "harvested":
            done[sh["stage"]] = done.get(sh["stage"], 0) + sh.get("harvested", sh.get("rows", 0))
        elif sh.get("status") == "failed":
            # a shard that hit the 24h wall is not zero progress -- it was salvaged
            done[sh["stage"]] = done.get(sh["stage"], 0) + sh.get("salvaged", 0)
        elif sh.get("status") == "submitted" and sh.get("job"):
            # Unharvested jobs are absent from the spend ledger. Keep their rows in
            # the future-cost estimate until harvest records the actual cost; live
            # completionStats must not make reserved work disappear from projection.
            continue
    rem_a = max(0, corpus_rows - done["pass_a"])
    rem_b = max(0, corpus_rows - done["pass_b"])
    rem_c = max(0, int(corpus_rows * conflict_rate) - done["pass_c"])
    fut = (rem_a*measured_cost(state,"pass_a") + rem_b*measured_cost(state,"pass_b")
           + rem_c*measured_cost(state,"pass_c"))
    return {"spent_thb": round(spent,2), "remaining": {"pass_a":rem_a,"pass_b":rem_b,"pass_c":rem_c},
            "future_thb": round(fut,2), "projected_total_thb": round(spent+fut,2),
            "per_row": {k: round(measured_cost(state,k),4) for k in PRIOR}}

def decide(p):
    tot = p["projected_total_thb"]; spent = p["spent_thb"]
    if spent >= HARDSTOP_THB:
        return "HALT", [f"spent THB {spent} >= hard stop {HARDSTOP_THB}; refuse all submission"]
    if tot > TARGET_THB:
        over = tot - TARGET_THB
        ladder = ["CUT ladder, in order, until projection <= target:",
                  "  1. drop multi-commit rows from unsubmitted shards (~-21% of A/B volume)",
                  "  2. Pass C thinking 2048 -> 1024",
                  "  3. patch trim cap 32KB -> 24KB (unsubmitted shards only; re-measure after)"]
        return "CUT", [f"projected THB {tot} exceeds target {TARGET_THB} by {over:.0f}"] + ladder
    if tot < FLOOR_THB:
        under = FLOOR_THB - tot
        return "STRETCH", [f"projected THB {tot} leaves {under:.0f} unused below floor {FLOOR_THB}",
                           "STRETCH ladder: extend Pass C to 'sibling' rows; retry analyzable=false rows",
                           "at thinking 2048; expand hand-verification sample"]
    return "PROCEED", [f"projected THB {tot} inside [{FLOOR_THB}, {TARGET_THB}]"]

def main():
    corpus = int(sys.argv[1]) if len(sys.argv) > 1 else 15600
    state = load_state()
    p = project(state, corpus)
    action, notes = decide(p)
    days = (EXPIRY - datetime.date.today()).days
    print(f"=== PATCHWORK GOVERNOR  {datetime.date.today()}  ({days} days to expiry) ===")
    print(f"corpus rows in scope : {corpus:,}")
    print(f"spent (self-accounted): THB {p['spent_thb']:,.2f}")
    print(f"remaining rows        : {p['remaining']}")
    print(f"per-row cost (THB)    : {p['per_row']}")
    print(f"future spend          : THB {p['future_thb']:,.2f}")
    print(f"PROJECTED TOTAL       : THB {p['projected_total_thb']:,.2f}   "
          f"(target {TARGET_THB}, hard stop {HARDSTOP_THB})")
    print(f"\nDECISION: {action}")
    for n in notes: print("  " + n)
    json.dump({"date": str(datetime.date.today()), "days_left": days, "action": action,
               **p}, open(os.path.join(R,"out","governor.json"),"w"), indent=1)

if __name__ == "__main__":
    main()
