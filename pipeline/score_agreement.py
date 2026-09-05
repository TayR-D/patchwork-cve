#!/usr/bin/env python3
"""Phase 6: join Pass A and Pass B, score CWE agreement, emit Pass C candidates.

Confidence in this dataset is *inter-model agreement scored against the MITRE CWE
hierarchy*, not any model's self-reported confidence -- which measured a useless
0.94 mean on the day-1 pilot while giving three different answers across three runs.

For two usable passes, exact / more_specific / more_general are COMPATIBLE (label
accepted, most specific wins). sibling / conflict go to Pass C adjudication.
Refused, malformed, incomplete, and missing passes are never compared.
"""
import json, os, sys, collections, subprocess
R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, "pipeline"))
import cwe_rel, batch, fetch_patches

ACCEPTED_FINISH_REASONS = {"STOP"}


def declared_analyzable(record):
    """Return the model's explicit analyzability decision, or ``None``.

    This is intentionally distinct from :func:`analysis_usable`: a malformed,
    truncated, or label-less response can say it is analyzable without being
    safe to use as a dataset label.
    """
    analysis = (record or {}).get("analysis")
    if not isinstance(analysis, dict):
        return None
    value = analysis.get("analyzable")
    return value if isinstance(value, bool) else None


def analysis_usable(record):
    """Whether one pass produced a complete, opted-in CWE analysis."""
    if not isinstance(record, dict) or record.get("parse_error"):
        return False
    if record.get("finish") not in ACCEPTED_FINISH_REASONS:
        return False
    analysis = record.get("analysis")
    if not isinstance(analysis, dict) or analysis.get("analyzable") is not True:
        return False
    cwe = cwe_rel.norm(analysis.get("cwe_primary"))
    return bool(cwe and cwe in cwe_rel.NAMES)


def canonical_record_key(record):
    """Deterministic preference order for duplicate/retried pass records."""
    analysis = record.get("analysis")
    complete = (
        not record.get("parse_error")
        and record.get("finish") == "STOP"
        and isinstance(analysis, dict)
    )
    analysis_text = record.get("_analysis_text")
    if not isinstance(analysis_text, str):
        analysis_text = json.dumps(analysis, sort_keys=True, separators=(",", ":"))
    return (
        analysis_usable(record),
        complete,
        str(record.get("shard") or ""),
        analysis_text,
        str(record.get("finish") or ""),
        str(record.get("parse_error") or ""),
        str(record.get("record_sha256") or ""),
    )


def analysis_pair_sha256(cve, patch_sha256, pro_record, flash_record):
    """Bind a Pass C decision to the exact two canonical source records."""
    pro_sha = (pro_record or {}).get("record_sha256")
    flash_sha = (flash_record or {}).get("record_sha256")
    pro_candidate = (pro_record or {}).get("candidate_fingerprint")
    flash_candidate = (flash_record or {}).get("candidate_fingerprint")
    if not pro_candidate or pro_candidate != flash_candidate:
        return None
    return batch.source_pair_sha256(
        cve, patch_sha256, pro_candidate, pro_sha, flash_sha
    )


def score_row(cve, pro_record, flash_record, candidate=None):
    """Score one CVE without ever treating a refusal as agreement evidence."""
    candidate = candidate or {}
    pa = (pro_record or {}).get("analysis")
    fb = (flash_record or {}).get("analysis")
    pa = pa if isinstance(pa, dict) else {}
    fb = fb if isinstance(fb, dict) else {}

    pc, fc = pa.get("cwe_primary"), fb.get("cwe_primary")
    pro_usable = analysis_usable(pro_record)
    flash_usable = analysis_usable(flash_record)
    crosscheck_usable = pro_usable and flash_usable
    advisory = candidate.get("cwe_ids") or []

    relation = cwe_final = label_source = None
    if crosscheck_usable:
        cwe_final, label_source, relation = cwe_rel.resolve(pc, fc)
        analysis_status = "crosschecked"
    elif pro_usable:
        cwe_final = cwe_rel.norm(pc)
        label_source = "single_model_unverified"
        analysis_status = "pro_only"
    elif flash_usable:
        cwe_final = cwe_rel.norm(fc)
        label_source = "single_model_unverified"
        analysis_status = "flash_only"
    else:
        analysis_status = "no_usable_analysis"

    reference_cwe = pc if pro_usable else fc if flash_usable else None
    advisory_relation = (cwe_rel.best_relation(reference_cwe, advisory)
                         if reference_cwe else None)
    patch_sha256 = candidate.get("patch_sha256")
    candidate_sha256 = candidate.get("candidate_fingerprint")
    return {
        "cve": cve,
        # Preserve raw model outputs for audit, including a disclaimed CWE.  The
        # usability fields below determine whether either value influenced a label.
        "cwe_pro": pc,
        "cwe_flash": fc,
        "relation": relation,
        "cwe_final": cwe_final,
        "label_source": label_source,
        "advisory_cwe": advisory,
        "advisory_relation": advisory_relation,
        "analyzable_pro": declared_analyzable(pro_record),
        "analyzable_flash": declared_analyzable(flash_record),
        "usable_pro": pro_usable,
        "usable_flash": flash_usable,
        "crosscheck_usable": crosscheck_usable,
        "analysis_status": analysis_status,
        "pass_pro_present": pro_record is not None,
        "pass_flash_present": flash_record is not None,
        "analysis_patch_sha256": patch_sha256,
        "analysis_candidate_fingerprint": candidate_sha256,
        "pass_pro_record_sha256": (pro_record or {}).get("record_sha256"),
        "pass_flash_record_sha256": (flash_record or {}).get("record_sha256"),
        "analysis_pair_sha256": analysis_pair_sha256(
            cve, patch_sha256, pro_record, flash_record
        ),
        "patch_sufficient_pro": pa.get("patch_sufficient") if pro_usable else None,
    }


def load_pass(stage, expected_patch_sha256=None, expected_candidate_fingerprint=None,
              expected_record_sha256=None):
    """Pull one deterministic, current-patch record per CVE from BigQuery."""
    if stage not in {"pass_a", "pass_b", "pass_c"}:
        raise ValueError(f"unsupported pass table: {stage}")
    q = (f"SELECT cve, model, shard, attempt_id, patch_sha256, "
         f"candidate_fingerprint, input_sha256, "
         f"record_sha256, analysis, finish, parse_error "
         f"FROM `{batch.PROJECT}.patchwork.{stage}`")
    cp = subprocess.run(["bq","--project_id="+batch.PROJECT,"query","--use_legacy_sql=false",
                         "--format=json","--max_rows=1000000",q],
                        capture_output=True, text=True, timeout=900)
    if cp.returncode != 0:
        raise RuntimeError(f"bq query {stage} failed: {cp.stderr[:400]}")
    grouped = collections.defaultdict(list)
    for r in json.loads(cp.stdout or "[]"):
        raw_analysis = r.get("analysis")
        a = raw_analysis
        # a failed analysis is stored as the string "null" (see session.bq_load)
        try:
            a = json.loads(a) if isinstance(a, str) else a
        except Exception:
            a = None
        cve = r.get("cve")
        if cve:
            if (expected_patch_sha256 is not None
                    and (cve not in expected_patch_sha256
                         or r.get("patch_sha256") != expected_patch_sha256[cve])):
                continue
            if (expected_candidate_fingerprint is not None
                    and (cve not in expected_candidate_fingerprint
                         or r.get("candidate_fingerprint")
                         != expected_candidate_fingerprint[cve])):
                continue
            if (expected_record_sha256 is not None
                    and (cve not in expected_record_sha256
                         or r.get("record_sha256") != expected_record_sha256[cve])):
                continue
            record = {
                "cve": cve,
                "model": r.get("model"),
                "analysis": a,
                "_analysis_text": raw_analysis,
                "finish": r.get("finish"),
                "parse_error": r.get("parse_error"),
                "shard": r.get("shard"),
                "attempt_id": r.get("attempt_id"),
                "patch_sha256": r.get("patch_sha256"),
                "candidate_fingerprint": r.get("candidate_fingerprint"),
                "input_sha256": r.get("input_sha256"),
                "record_sha256": r.get("record_sha256"),
            }
            if (not record["record_sha256"]
                    or batch.analysis_record_sha256(record) != record["record_sha256"]):
                continue
            grouped[cve].append(record)
    return {cve: max(records, key=canonical_record_key)
            for cve, records in grouped.items()}


def main():
    with open(f"{R}/out/candidates.jsonl") as candidate_file:
        rows = {}
        for line in candidate_file:
            row = json.loads(line)
            rows[row["cve"]] = row
    statuses = fetch_patches.load_latest_status(f"{R}/out/fetch_status.jsonl")
    patch_dir = f"{R}/out/patches"
    expected_patch_sha256 = {}
    expected_candidate_fingerprint = {}
    for cve, row in rows.items():
        status = statuses.get(cve, {})
        if fetch_patches.status_matches_patch(status, row, patch_dir=patch_dir):
            expected_patch_sha256[cve] = status["patch_sha256"]
            row["patch_sha256"] = status["patch_sha256"]
            fingerprint = fetch_patches.candidate_fingerprint(
                row, status["patch_sha256"]
            )
            expected_candidate_fingerprint[cve] = fingerprint
            row["candidate_fingerprint"] = fingerprint
    pro = load_pass(
        "pass_a", expected_patch_sha256, expected_candidate_fingerprint
    )
    fla = load_pass(
        "pass_b", expected_patch_sha256, expected_candidate_fingerprint
    )
    cves = sorted(rows)
    print(f"pass_a={len(pro):,}  pass_b={len(fla):,}  candidates={len(cves):,}")

    rel_c = collections.Counter(); adv_c = collections.Counter(); status_c = collections.Counter()
    scored, adjudicate = [], []
    for c in cves:
        rec = score_row(c, pro.get(c), fla.get(c), rows[c])
        scored.append(rec)
        status_c[rec["analysis_status"]] += 1
        if rec["relation"]:
            rel_c[rec["relation"]] += 1
        if rec["advisory_relation"]:
            adv_c[rec["advisory_relation"]] += 1
        if rec["label_source"] == "needs_adjudication":
            adjudicate.append(c)

    n = status_c["crosschecked"]
    compat = sum(rel_c[k] for k in ("exact","more_specific","more_general"))
    print("\nAnalysis status:")
    for k, v in status_c.most_common(): print(f"   {k:<20} {v:>6}")
    print("\nPro vs Flash (usable cross-checks only):")
    for k, v in rel_c.most_common():
        print(f"   {k:<15} {v:>6}  {v/n*100:>5.1f}%" if n else f"   {k:<15} {v:>6}")
    if n:
        print(f"   => compatible {compat:,}/{n:,} = {compat/n*100:.1f}%")
        print(f"   => adjudicate {len(adjudicate):,} = {len(adjudicate)/n*100:.1f}%")
    print("\nUsable analysis vs advisory CWE:")
    adv_n = sum(adv_c.values())
    for k, v in adv_c.most_common():
        print(f"   {k:<15} {v:>6}  {v/adv_n*100:>5.1f}%" if adv_n else f"   {k:<15} {v:>6}")

    with open(f"{R}/out/agreement.jsonl","w") as fh:
        for r in scored: fh.write(json.dumps(r)+"\n")
    with open(f"{R}/out/adjudicate_cves.json", "w") as adjudicate_file:
        json.dump(adjudicate, adjudicate_file)
    print(f"\n-> out/agreement.jsonl ({len(scored):,} rows)")
    print(f"-> out/adjudicate_cves.json ({len(adjudicate):,} Pass C candidates)")

if __name__ == "__main__":
    main()
