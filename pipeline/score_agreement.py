#!/usr/bin/env python3
"""Phase 6: join Pass A and Pass B, score CWE agreement, emit Pass C candidates.

Confidence in this dataset is *inter-model agreement scored against the MITRE CWE
hierarchy*, not any model's self-reported confidence -- which measured a useless
0.94 mean on the day-1 pilot while giving three different answers across three runs.

Relations: exact / more_specific / more_general are COMPATIBLE (label accepted,
most specific wins). sibling / conflict go to Pass C adjudication. Disagreement is
recorded on every row either way -- never silently resolved.
"""
import json, os, sys, collections, subprocess
R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, "scripts"))
import cwe_rel, batch

def load_pass(stage):
    """Pull one pass out of BigQuery into {cve: analysis}."""
    q = (f"SELECT cve, analysis, finish, parse_error, tokens_in, tokens_out "
         f"FROM `{batch.PROJECT}.patchwork.{stage}`")
    cp = subprocess.run(["bq","--project_id="+batch.PROJECT,"query","--use_legacy_sql=false",
                         "--format=json","--max_rows=100000",q],
                        capture_output=True, text=True, timeout=900)
    if cp.returncode != 0:
        raise RuntimeError(f"bq query {stage} failed: {cp.stderr[:400]}")
    out = {}
    for r in json.loads(cp.stdout or "[]"):
        a = r.get("analysis")
        # a failed analysis is stored as the string "null" (see session.bq_load)
        try:
            a = json.loads(a) if isinstance(a, str) else a
        except Exception:
            a = None
        if r.get("cve"): out[r["cve"]] = {"analysis": a, "finish": r.get("finish")}
    return out

def main():
    pro = load_pass("pass_a"); fla = load_pass("pass_b")
    rows = {json.loads(l)["cve"]: json.loads(l) for l in open(f"{R}/out/candidates.jsonl")}
    both = [c for c in pro if c in fla]
    print(f"pass_a={len(pro):,}  pass_b={len(fla):,}  joined={len(both):,}")

    rel_c = collections.Counter(); adv_c = collections.Counter()
    scored, adjudicate = [], []
    for c in both:
        pa = pro[c]["analysis"] or {}; fb = fla[c]["analysis"] or {}
        pc, fc = pa.get("cwe_primary"), fb.get("cwe_primary")
        rel = cwe_rel.relation(pc, fc); rel_c[rel] += 1
        adv = rows.get(c, {}).get("cwe_ids") or []
        adv_rel = cwe_rel.best_relation(pc, adv); adv_c[adv_rel] += 1
        label, source, _ = cwe_rel.resolve(pc, fc)
        rec = {"cve": c, "cwe_pro": pc, "cwe_flash": fc, "relation": rel,
               "cwe_final": label, "label_source": source,
               "advisory_cwe": adv, "advisory_relation": adv_rel,
               "analyzable_pro": pa.get("analyzable"), "analyzable_flash": fb.get("analyzable"),
               "patch_sufficient_pro": pa.get("patch_sufficient")}
        scored.append(rec)
        if source == "needs_adjudication":
            adjudicate.append(c)

    n = len(both)
    compat = sum(rel_c[k] for k in ("exact","more_specific","more_general"))
    print(f"\nPro vs Flash:")
    for k, v in rel_c.most_common(): print(f"   {k:<15} {v:>6}  {v/n*100:>5.1f}%")
    print(f"   => compatible {compat:,}/{n:,} = {compat/n*100:.1f}%")
    print(f"   => adjudicate {len(adjudicate):,} = {len(adjudicate)/n*100:.1f}%")
    print(f"\nPro vs advisory CWE:")
    for k, v in adv_c.most_common(): print(f"   {k:<15} {v:>6}  {v/n*100:>5.1f}%")

    with open(f"{R}/out/agreement.jsonl","w") as fh:
        for r in scored: fh.write(json.dumps(r)+"\n")
    json.dump(adjudicate, open(f"{R}/out/adjudicate_cves.json","w"))
    print(f"\n-> out/agreement.jsonl ({len(scored):,} rows)")
    print(f"-> out/adjudicate_cves.json ({len(adjudicate):,} Pass C candidates)")

if __name__ == "__main__":
    main()
