#!/usr/bin/env python3
"""Pass C driver: build, submit and harvest adjudication shards.

Runs after score_agreement.py has produced out/adjudicate_cves.json. Uses 4-6
shards in flight (not the maximum) so shards complete progressively -- Pro
throughput is globally capped, so extra concurrency only spreads it thinner.
"""
import json, os, sys, collections, uuid
R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, "pipeline"))
import batch, ledger, adjudicate, session

SHARD_ROWS = int(os.environ.get("PW_C_SHARD_ROWS", "700"))
INFLIGHT   = int(os.environ.get("PW_INFLIGHT_C", "4"))
STATE      = os.path.join(R, "state", "pass_c.json")

CACHE = os.path.join(R, "out", "pass_c_analyses.json")


def eligible_for_adjudication(pro_record, flash_record):
    """Defence-in-depth for stale candidate lists and cached pass outputs."""
    import score_agreement as sa
    if not (sa.analysis_usable(pro_record) and sa.analysis_usable(flash_record)):
        return False
    pro_cwe = pro_record["analysis"].get("cwe_primary")
    flash_cwe = flash_record["analysis"].get("cwe_primary")
    return sa.cwe_rel.resolve(pro_cwe, flash_cwe)[1] == "needs_adjudication"


def load_analyses():
    """Pro+Flash analyses for the adjudication candidates only.

    Cached to disk: the loop calls this every cycle, and re-pulling 33k rows from
    BigQuery each time is slow and pointless -- the analyses are immutable now that
    Pass A and B are complete.
    """
    import score_agreement as sa
    with open(f"{R}/out/adjudicate_cves.json", encoding="utf-8") as want_file:
        want = set(json.load(want_file))
    with open(f"{R}/out/candidates.jsonl", encoding="utf-8") as candidate_file:
        rows = {row["cve"]: row for row in
                (json.loads(line) for line in candidate_file)
                if row["cve"] in want}
    with open(f"{R}/out/agreement.jsonl", encoding="utf-8") as agreement_file:
        agreement = {
            row["cve"]: row for row in
            (json.loads(line) for line in agreement_file)
            if row["cve"] in want
        }
    statuses = batch.fetch_patches.load_latest_status(f"{R}/out/fetch_status.jsonl")
    selection = {}
    for cve, row in rows.items():
        status = statuses.get(cve, {})
        scored = agreement.get(cve, {})
        if not batch.fetch_patches.status_matches_patch(
                status, row, patch_dir=f"{R}/out/patches"):
            continue
        patch_sha256 = status["patch_sha256"]
        candidate_sha256 = batch.fetch_patches.candidate_fingerprint(
            row, patch_sha256
        )
        pro_sha = scored.get("pass_pro_record_sha256")
        flash_sha = scored.get("pass_flash_record_sha256")
        expected_pair = sa.analysis_pair_sha256(
            cve, patch_sha256,
            {"record_sha256": pro_sha,
             "candidate_fingerprint": candidate_sha256},
            {"record_sha256": flash_sha,
             "candidate_fingerprint": candidate_sha256},
        )
        if (not expected_pair
                or scored.get("label_source") != "needs_adjudication"
                or scored.get("crosscheck_usable") is not True
                or scored.get("analysis_patch_sha256") != patch_sha256
                or scored.get("analysis_candidate_fingerprint") != candidate_sha256
                or scored.get("analysis_pair_sha256") != expected_pair):
            continue
        selection[cve] = {
            "patch_sha256": patch_sha256,
            "candidate_fingerprint": candidate_sha256,
            "pro_record_sha256": pro_sha,
            "flash_record_sha256": flash_sha,
            "analysis_pair_sha256": expected_pair,
        }
    selection_sha256 = batch.stable_sha256(selection)
    if os.path.exists(CACHE):
        with open(CACHE, encoding="utf-8") as cache_file:
            d = json.load(cache_file)
        cached_pro, cached_flash = d.get("pro", {}), d.get("flash", {})
        cache_records_match = all(
            cached_pro.get(cve, {}).get("record_sha256") == item["pro_record_sha256"]
            and cached_flash.get(cve, {}).get("record_sha256") == item["flash_record_sha256"]
            and batch.analysis_record_sha256(cached_pro[cve])
                == item["pro_record_sha256"]
            and batch.analysis_record_sha256(cached_flash[cve])
                == item["flash_record_sha256"]
            for cve, item in selection.items()
        ) and set(cached_pro) == set(selection) == set(cached_flash)
        if d.get("selection_sha256") == selection_sha256 and cache_records_match:
            return d["pro"], d["flash"]
    expected_patch_sha256 = {cve: item["patch_sha256"]
                             for cve, item in selection.items()}
    expected_candidate = {cve: item["candidate_fingerprint"]
                          for cve, item in selection.items()}
    expected_pro = {cve: item["pro_record_sha256"]
                    for cve, item in selection.items()}
    expected_flash = {cve: item["flash_record_sha256"]
                      for cve, item in selection.items()}
    pro = sa.load_pass(
        "pass_a", expected_patch_sha256, expected_candidate, expected_pro
    )
    fla = sa.load_pass(
        "pass_b", expected_patch_sha256, expected_candidate, expected_flash
    )
    with open(CACHE, "w") as cache_file:
        json.dump({"selection_sha256": selection_sha256,
                   "pro": pro, "flash": fla}, cache_file)
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
    import score_agreement as sa
    shard_id = batch.validate_shard(sh["id"])
    attempt_id = uuid.uuid4().hex
    sh["attempt_id"] = attempt_id
    local = os.path.join(
        R, "out", "batch_in", f"{shard_id}.{attempt_id}.jsonl"
    )
    os.makedirs(os.path.dirname(local), exist_ok=True)
    kept, slots, index_rows = [], {}, []
    statuses = batch.fetch_patches.load_latest_status(
        os.path.join(R, "out", "fetch_status.jsonl")
    )
    with open(local, "w") as fh:
        for cve in sh["cves"]:
            row = rows.get(cve)
            pro_record, flash_record = pro.get(cve), fla.get(cve)
            pa = (pro_record or {}).get("analysis")
            fb = (flash_record or {}).get("analysis")
            pf = batch.verified_patch_path(row, statuses) if row else None
            expected_patch_sha256 = statuses.get(cve, {}).get("patch_sha256")
            candidate_sha256 = batch.fetch_patches.candidate_fingerprint(
                row, expected_patch_sha256
            ) if row else None
            analyses_match_patch = (
                pro_record is not None and flash_record is not None
                and pro_record.get("patch_sha256") == expected_patch_sha256
                and flash_record.get("patch_sha256") == expected_patch_sha256
                and pro_record.get("candidate_fingerprint") == candidate_sha256
                and flash_record.get("candidate_fingerprint") == candidate_sha256
                and pro_record.get("record_sha256")
                and flash_record.get("record_sha256")
            )
            if not (pf and analyses_match_patch
                    and eligible_for_adjudication(pro_record, flash_record)):
                continue
            with open(pf, encoding="utf-8", errors="replace") as patch_file:
                patch_text = patch_file.read()
            body, sl = adjudicate.build_adj_request(
                row, pa, fb, patch_text, thinking=sh["thinking"])
            pair_sha256 = sa.analysis_pair_sha256(
                cve, expected_patch_sha256, pro_record, flash_record
            )
            input_sha256 = batch.attach_request_provenance(
                body, attempt_id, expected_patch_sha256, candidate_sha256,
                pair_sha256, pro_record["record_sha256"],
                flash_record["record_sha256"],
            )
            fh.write(json.dumps({"request": body}) + "\n")
            kept.append(cve); slots[cve] = sl
            index_rows.append({
                "cve": cve,
                "patch_sha256": expected_patch_sha256,
                "candidate_fingerprint": candidate_sha256,
                "input_sha256": input_sha256,
                "analysis_pair_sha256": pair_sha256,
                "pass_pro_record_sha256": pro_record["record_sha256"],
                "pass_flash_record_sha256": flash_record["record_sha256"],
            })
    input_uri = f"{batch.BUCKET}/batch_in/{shard_id}/{attempt_id}.jsonl"
    batch.gs("cp", local, input_uri)
    slot_path = os.path.join(
        R, "out", "batch_in", f"{shard_id}.{attempt_id}.slots.json"
    )
    with open(slot_path, "w") as slot_file:
        json.dump({"rows": kept, "slots": slots}, slot_file)
    index_path = os.path.join(
        R, "out", "batch_in", f"{shard_id}.{attempt_id}.index.json"
    )
    with open(index_path, "w") as index_file:
        json.dump({"shard": shard_id, "attempt_id": attempt_id,
                   "model": sh.get("model"), "input_uri": input_uri,
                   "rows": index_rows}, index_file)
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
            recs, errs, cost = batch.harvest(
                sh["id"], sh["model"], sh.get("attempt_id")
            )
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
        j = batch.submit(sh["id"], sh["model"], sh["attempt_id"])
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
