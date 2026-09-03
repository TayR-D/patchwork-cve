#!/usr/bin/env python3
"""Phase 7: assemble the publishable dataset.

Local Parquet writing is impossible here (no pyarrow/pandas/pip), so BigQuery does
the join and the export. Steps:

  load    candidates metadata + agreement scores into BigQuery
  build   patchwork.dataset_final -- one row per CVE, all passes joined
  split   hold out a stratified benchmark set
  export  Parquet (via bq extract) + JSONL.gz to GCS, then pull down locally

Licensing posture, as pitched: rows carry commit pointers, patch SHA256 and minimal
hunk excerpts -- NOT wholesale source -- with a reconstruction script in the release.
Model-generated fields are flagged `synthetic` so downstream users can separate the
factual backbone (public CVE + public diff) from the analysis layer.
"""
import json, os, sys, subprocess, hashlib, gzip, collections
R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, "scripts"))
import batch

P = batch.PROJECT
BUCKET = batch.BUCKET
DS = "patchwork"

def bq(*args, timeout=1800):
    cp = subprocess.run(["bq", "--project_id="+P, *args], capture_output=True, text=True, timeout=timeout)
    if cp.returncode != 0:
        raise RuntimeError(f"bq {args[0]} failed: {cp.stderr[:500]}")
    return cp.stdout

def load_candidates():
    """Flatten candidates.jsonl into a BQ-friendly shape and load it."""
    tmp = f"{R}/out/_candidates_bq.jsonl"
    n = 0
    with open(tmp, "w") as out:
        for l in open(f"{R}/out/candidates.jsonl"):
            d = json.loads(l)
            c = d["commits"][0]
            pf = f"{R}/out/patches/{d['cve']}.patch"
            if not os.path.exists(pf):
                continue
            raw = open(pf, "rb").read()
            out.write(json.dumps({
                "cve": d["cve"], "osv_id": d["osv_id"], "ecosystem": d["ecosystem"],
                "packages": d["packages"], "summary": d["summary"],
                "cvss": d.get("cvss"), "advisory_cwe": d.get("cwe_ids") or [],
                "published": d.get("published"), "n_commits": d["n_commits"],
                "repo_owner": c["owner"], "repo_name": c["repo"], "fix_sha": c["sha"],
                "patch_sha256": hashlib.sha256(raw).hexdigest(),
                "patch_bytes": len(raw),
            }) + "\n"); n += 1
    bq("load", "--source_format=NEWLINE_DELIMITED_JSON", "--autodetect", "--replace=true",
       f"{DS}.candidates", tmp)
    print(f"  loaded {n:,} candidates")
    return n

def load_agreement():
    f = f"{R}/out/agreement.jsonl"
    if not os.path.exists(f):
        print("  (no agreement.jsonl yet -- run score_agreement.py first)"); return 0
    bq("load", "--source_format=NEWLINE_DELIMITED_JSON", "--autodetect", "--replace=true",
       f"{DS}.agreement", f)
    n = sum(1 for _ in open(f))
    print(f"  loaded {n:,} agreement rows")
    return n

FINAL_SQL = f"""
CREATE OR REPLACE TABLE `{P}.{DS}.dataset_final` AS
WITH c AS (SELECT * FROM `{P}.{DS}.candidates`),
     a AS (SELECT cve, analysis AS analysis_pro, finish AS finish_pro FROM `{P}.{DS}.pass_a`
           WHERE analysis IS NOT NULL AND analysis != 'null'),
     b AS (SELECT cve, analysis AS analysis_flash FROM `{P}.{DS}.pass_b`
           WHERE analysis IS NOT NULL AND analysis != 'null'),
     adj AS (SELECT cve,
                    JSON_VALUE(analysis,'$.cwe_final')                AS cwe_adjudicated,
                    JSON_VALUE(analysis,'$.chose')                    AS adj_chose,
                    JSON_VALUE(analysis,'$.rationale')                AS adj_rationale,
                    CAST(JSON_VALUE(analysis,'$.both_defensible') AS BOOL)  AS adj_both_defensible,
                    CAST(JSON_VALUE(analysis,'$.adjudication_confidence') AS FLOAT64) AS adj_confidence
             FROM `{P}.{DS}.pass_c`
             WHERE analysis IS NOT NULL AND analysis != 'null'),
     g AS (SELECT * FROM `{P}.{DS}.agreement`)
SELECT
  c.cve, c.osv_id, c.ecosystem, c.packages, c.summary, c.cvss,
  c.advisory_cwe, c.published, c.n_commits,
  c.repo_owner, c.repo_name, c.fix_sha, c.patch_sha256, c.patch_bytes,
  -- both independent analyses, always preserved
  g.cwe_pro, g.cwe_flash, g.relation, g.advisory_relation,
  -- adjudication layer (only present where the models genuinely diverged)
  adj.cwe_adjudicated, adj.adj_chose, adj.adj_rationale,
  adj.adj_both_defensible, adj.adj_confidence,
  -- the single label a consumer should use, and where it came from
  -- 22 rows have no Pass B analysis, so no cross-check was possible. They fall back
  -- to the Pro label, explicitly marked unverified rather than left null or passed
  -- off as agreement-backed.
  COALESCE(adj.cwe_adjudicated, g.cwe_final, g.cwe_pro) AS cwe_final,
  CASE WHEN adj.cwe_adjudicated IS NOT NULL           THEN 'adjudicated'
       WHEN g.cwe_final IS NOT NULL                   THEN g.label_source
       WHEN b.analysis_flash IS NULL AND g.cwe_pro IS NOT NULL
            THEN 'single_model_unverified'
       ELSE g.label_source END                        AS label_source,
  g.patch_sufficient_pro,
  -- surfaced from the JSON so consumers can filter without parsing:
  -- when analyzable=false the model DECLINED to analyse this diff, yet the schema
  -- still required a cwe_primary, so a CWE is present but should not be trusted.
  COALESCE(JSON_VALUE(a.analysis_pro,'$.analyzable') != 'false', TRUE) AS analyzable,
  (COALESCE(JSON_VALUE(a.analysis_pro,'$.detection_heuristic'),'') != '') AS has_detection_heuristic,
  a.analysis_pro, b.analysis_flash,
  TRUE AS analysis_is_model_generated
FROM c
JOIN a USING (cve)
LEFT JOIN b   USING (cve)
LEFT JOIN g   USING (cve)
LEFT JOIN adj USING (cve)
"""

def build_final():
    bq("query", "--use_legacy_sql=false", "--nouse_cache", FINAL_SQL)
    n = json.loads(bq("query", "--use_legacy_sql=false", "--format=json",
                      f"SELECT COUNT(*) n FROM `{P}.{DS}.dataset_final`"))[0]["n"]
    print(f"  dataset_final: {n} rows")
    return int(n)

def export(table, name):
    prefix = f"{BUCKET}/export/{name}"
    bq("extract", "--destination_format=PARQUET", "--compression=SNAPPY",
       f"{DS}.{table}", f"{prefix}/{name}-*.parquet")
    bq("extract", "--destination_format=NEWLINE_DELIMITED_JSON", "--compression=GZIP",
       f"{DS}.{table}", f"{prefix}/{name}-*.jsonl.gz")
    os.makedirs(f"{R}/out/release", exist_ok=True)
    subprocess.run(["gcloud","storage","cp","-r",f"{prefix}",f"{R}/out/release/"],
                   capture_output=True, timeout=1800)
    print(f"  exported {table} -> {prefix} (+ local out/release/{name})")

if __name__ == "__main__":
    step = sys.argv[1] if len(sys.argv) > 1 else "all"
    if step in ("all","load"): load_candidates(); load_agreement()
    if step in ("all","build"): build_final()
    if step in ("all","export"): export("dataset_final", "patchwork-cve")
