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
import json, os, re, sys, subprocess, hashlib
R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, "pipeline"))
import batch, cwe_rel

P = batch.PROJECT
BUCKET = batch.BUCKET
DS = "patchwork"
FETCH_STATUS = os.path.join(R, "out", "fetch_status.jsonl")
PATCH_FORMAT = "github-commit-dot-patch-v1"
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")
CANDIDATE_SCHEMA = os.path.join(R, "schema", "bq_candidates.json")
AGREEMENT_SCHEMA = os.path.join(R, "schema", "bq_agreement.json")

def bq(*args, timeout=1800):
    cp = subprocess.run(["bq", "--project_id="+P, *args], capture_output=True, text=True, timeout=timeout)
    if cp.returncode != 0:
        raise RuntimeError(f"bq {args[0]} failed: {cp.stderr[:500]}")
    return cp.stdout


def load_fetch_status(path=FETCH_STATUS):
    """Load latest statuses, ignoring only an interrupted final append."""
    latest = {}
    try:
        source = open(path, encoding="utf-8")
    except FileNotFoundError as error:
        raise RuntimeError(
            "missing out/fetch_status.jsonl; rerun pipeline/fetch_patches.py "
            "to create versioned reconstruction provenance"
        ) from error
    with source:
        lines = source.readlines()
        for line_number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                status = json.loads(line)
            except json.JSONDecodeError as error:
                if line_number == len(lines) and not line.endswith("\n"):
                    print(
                        f"  warning: ignoring incomplete final fetch status line "
                        f"{line_number}", file=sys.stderr
                    )
                    continue
                raise RuntimeError(
                    f"invalid fetch status JSON on line {line_number}: {error.msg}"
                ) from error
            cve = status.get("cve")
            if cve:
                latest[cve] = status
    return latest


def release_patch_metadata(candidate, status, raw):
    """Return verified release provenance, or ``None`` for an ineligible patch."""
    commits = status.get("patch_commits")
    try:
        expected_commits = int(candidate["n_commits"])
        fetched_commits = int(status["n_fetched"])
        status_commits = int(status["n_commits"])
    except (KeyError, TypeError, ValueError):
        return None
    if (
        status.get("status") != "ok"
        or status.get("patch_format") != PATCH_FORMAT
        or not isinstance(commits, list)
        or not commits
        or fetched_commits != expected_commits
        or status_commits != expected_commits
        or len(commits) != expected_commits
        or status.get("patch_partial_fetch") is not False
        or any(
            commit.get("included") is not True
            or commit.get("fetch_status") != "ok"
            for commit in commits
        )
    ):
        return None
    candidate_commits = candidate.get("commits") or []
    if len(candidate_commits) != expected_commits:
        return None
    for expected_commit, recorded_commit in zip(candidate_commits, commits):
        expected_identity = tuple(
            str(expected_commit.get(field) or "").lower()
            for field in ("owner", "repo", "sha")
        )
        recorded_identity = tuple(
            str(recorded_commit.get(field) or "").lower()
            for field in ("owner", "repo", "sha")
        )
        if not all(expected_identity) or recorded_identity != expected_identity:
            return None
    digest = hashlib.sha256(raw).hexdigest()
    if status.get("patch_sha256") != digest:
        return None
    return {
        "patch_sha256": digest,
        "patch_bytes": len(raw),
        "patch_format": status["patch_format"],
        "patch_representation": status.get("patch_representation"),
        "patch_joiner": status.get("patch_joiner"),
        "patch_max_bytes_per_commit": status.get("patch_max_bytes_per_commit"),
        "patch_truncated": bool(status.get("patch_truncated")),
        "patch_partial_fetch": False,
        "patch_complete": bool(status.get("patch_complete")),
        "patch_commits": commits,
    }

def load_candidates():
    """Load only candidates whose patch bytes have reproducible provenance."""
    tmp = f"{R}/out/_candidates_bq.jsonl"
    statuses = load_fetch_status()
    n = skipped = 0
    seen = set()
    with open(tmp, "w") as out:
        for l in open(f"{R}/out/candidates.jsonl"):
            d = json.loads(l)
            if not isinstance(d.get("cve"), str) or CVE_RE.fullmatch(d["cve"]) is None:
                skipped += 1
                continue
            if d["cve"] in seen:
                raise RuntimeError(f"duplicate candidate CVE: {d['cve']}")
            seen.add(d["cve"])
            c = d["commits"][0]
            pf = f"{R}/out/patches/{d['cve']}.patch"
            if not os.path.exists(pf):
                skipped += 1
                continue
            raw = open(pf, "rb").read()
            patch_metadata = release_patch_metadata(d, statuses.get(d["cve"], {}), raw)
            if patch_metadata is None:
                skipped += 1
                continue
            candidate_fingerprint = batch.fetch_patches.candidate_fingerprint(
                d, patch_metadata["patch_sha256"]
            )
            out.write(json.dumps({
                "cve": d["cve"], "osv_id": d["osv_id"], "ecosystem": d["ecosystem"],
                "packages": d["packages"], "summary": d["summary"],
                "cvss": d.get("cvss"), "advisory_cwe": d.get("cwe_ids") or [],
                "published": d.get("published"), "n_commits": d["n_commits"],
                "repo_owner": c["owner"], "repo_name": c["repo"], "fix_sha": c["sha"],
                "candidate_fingerprint": candidate_fingerprint,
                **patch_metadata,
            }) + "\n"); n += 1
    bq("load", "--source_format=NEWLINE_DELIMITED_JSON",
       f"--schema={CANDIDATE_SCHEMA}", "--replace=true",
       f"{DS}.candidates", tmp)
    print(f"  loaded {n:,} candidates ({skipped:,} skipped: missing/unverified patch provenance)")
    return n

def load_agreement():
    f = f"{R}/out/agreement.jsonl"
    if not os.path.exists(f):
        print("  (no agreement.jsonl yet -- run score_agreement.py first)"); return 0
    seen = set()
    n = 0
    with open(f, encoding="utf-8") as agreement_file:
        for line_number, line in enumerate(agreement_file, 1):
            row = json.loads(line)
            cve = row.get("cve")
            if not cve or cve in seen:
                raise RuntimeError(
                    f"missing or duplicate agreement CVE on line {line_number}: {cve}"
                )
            seen.add(cve)
            n += 1
    bq("load", "--source_format=NEWLINE_DELIMITED_JSON",
       f"--schema={AGREEMENT_SCHEMA}", "--replace=true",
       f"{DS}.agreement", f)
    print(f"  loaded {n:,} agreement rows")
    return n

VALID_CWE_SQL = "[" + ",".join(f"'{cwe}'" for cwe in sorted(cwe_rel.NAMES)) + "]"


def normalized_json_cwe_sql(alias, field):
    raw = f"JSON_VALUE({alias}.analysis,'$.{field}')"
    cleaned = f"REPLACE(UPPER(TRIM({raw})), ' ', '')"
    return (
        f"CASE WHEN SAFE_CAST({cleaned} AS INT64) IS NOT NULL "
        f"THEN CONCAT('CWE-', CAST(SAFE_CAST({cleaned} AS INT64) AS STRING)) "
        f"ELSE {cleaned} END"
    )


def source_pass_usable_sql(alias):
    cwe = normalized_json_cwe_sql(alias, "cwe_primary")
    return (
        f"{alias}.finish = 'STOP' AND {alias}.parse_error IS NULL "
        f"AND {alias}.analysis IS NOT NULL AND {alias}.analysis != 'null' "
        f"AND SAFE_CAST(JSON_VALUE({alias}.analysis,'$.analyzable') AS BOOL) IS TRUE "
        f"AND {cwe} IN UNNEST({VALID_CWE_SQL})"
    )


def adjudication_usable_sql(alias):
    cwe = normalized_json_cwe_sql(alias, "cwe_final")
    confidence = (
        f"SAFE_CAST(JSON_VALUE({alias}.analysis,'$.adjudication_confidence') AS FLOAT64)"
    )
    return (
        f"{alias}.finish = 'STOP' AND {alias}.parse_error IS NULL "
        f"AND {alias}.analysis IS NOT NULL AND {alias}.analysis != 'null' "
        f"AND {cwe} IN UNNEST({VALID_CWE_SQL}) "
        f"AND JSON_VALUE({alias}.analysis,'$.chose') "
        f"IN ('analysis_1','analysis_2','neither') "
        f"AND COALESCE(JSON_VALUE({alias}.analysis,'$.rationale'),'') != '' "
        f"AND SAFE_CAST(JSON_VALUE({alias}.analysis,'$.both_defensible') AS BOOL) "
        f"IS NOT NULL AND {confidence} BETWEEN 0 AND 1"
    )


def canonical_pass_sql(stage, usable_sql):
    if stage not in {"pass_a", "pass_b", "pass_c"}:
        raise ValueError(f"unsupported pass table: {stage}")
    complete = (
        "p.finish = 'STOP' AND p.parse_error IS NULL "
        "AND p.analysis IS NOT NULL AND p.analysis != 'null'"
    )
    return f"""
SELECT *
FROM `{P}.{DS}.{stage}` AS p
WHERE p.cve IS NOT NULL
  AND p.patch_sha256 IS NOT NULL
  AND p.candidate_fingerprint IS NOT NULL
  AND p.record_sha256 IS NOT NULL
QUALIFY ROW_NUMBER() OVER (
  PARTITION BY p.cve, p.patch_sha256, p.candidate_fingerprint
  ORDER BY IF({usable_sql}, 1, 0) DESC,
           IF({complete}, 1, 0) DESC,
           COALESCE(p.shard, '') DESC,
           COALESCE(p.analysis, '') DESC,
           COALESCE(p.finish, '') DESC,
           COALESCE(p.parse_error, '') DESC
) = 1
""".strip()


def deduplicated_pass_records_sql(stage):
    """Keep one physical row per immutable harvested-record fingerprint."""
    if stage not in {"pass_a", "pass_b", "pass_c"}:
        raise ValueError(f"unsupported pass table: {stage}")
    return f"""
SELECT *
FROM `{P}.{DS}.{stage}` AS p
WHERE p.cve IS NOT NULL
  AND p.patch_sha256 IS NOT NULL
  AND p.candidate_fingerprint IS NOT NULL
  AND p.record_sha256 IS NOT NULL
QUALIFY ROW_NUMBER() OVER (
  PARTITION BY p.cve, p.patch_sha256, p.candidate_fingerprint, p.record_sha256
  ORDER BY COALESCE(p.attempt_id, '') DESC,
           COALESCE(p.shard, '') DESC,
           COALESCE(p.analysis, '') DESC
) = 1
""".strip()


PASS_A_ONE_SQL = canonical_pass_sql("pass_a", source_pass_usable_sql("p"))
PASS_B_ONE_SQL = canonical_pass_sql("pass_b", source_pass_usable_sql("p"))
PASS_A_RECORDS_SQL = deduplicated_pass_records_sql("pass_a")
PASS_B_RECORDS_SQL = deduplicated_pass_records_sql("pass_b")
PASS_C_RECORDS_SQL = deduplicated_pass_records_sql("pass_c")
PASS_C_ONE_SQL = f"""
SELECT *
FROM ({PASS_C_RECORDS_SQL}) AS p
WHERE p.analysis_pair_sha256 IS NOT NULL
QUALIFY ROW_NUMBER() OVER (
  PARTITION BY p.cve, p.patch_sha256, p.candidate_fingerprint,
               p.analysis_pair_sha256
  ORDER BY IF({adjudication_usable_sql('p')}, 1, 0) DESC,
           IF(p.finish = 'STOP' AND p.parse_error IS NULL
              AND p.analysis IS NOT NULL AND p.analysis != 'null', 1, 0) DESC,
           COALESCE(p.attempt_id, '') DESC,
           COALESCE(p.record_sha256, '') DESC
) = 1
""".strip()


FINAL_SQL = f"""
CREATE OR REPLACE TABLE `{P}.{DS}.dataset_final` AS
WITH c AS (SELECT * FROM `{P}.{DS}.candidates`),
     pass_a_records AS ({PASS_A_RECORDS_SQL}),
     pass_b_records AS ({PASS_B_RECORDS_SQL}),
     pass_c_one AS ({PASS_C_ONE_SQL}),
     a AS (SELECT cve, patch_sha256, candidate_fingerprint, record_sha256,
                  NULLIF(analysis, 'null') AS analysis_pro,
                  finish AS finish_pro
           FROM pass_a_records),
     b AS (SELECT cve, patch_sha256, candidate_fingerprint, record_sha256,
                  NULLIF(analysis, 'null') AS analysis_flash
           FROM pass_b_records),
     adj AS (SELECT cve, patch_sha256, candidate_fingerprint, analysis_pair_sha256,
                    {normalized_json_cwe_sql('p', 'cwe_final')}       AS cwe_adjudicated,
                    JSON_VALUE(analysis,'$.chose')                    AS adj_chose,
                    JSON_VALUE(analysis,'$.rationale')                AS adj_rationale,
                    CAST(JSON_VALUE(analysis,'$.both_defensible') AS BOOL)  AS adj_both_defensible,
                    CAST(JSON_VALUE(analysis,'$.adjudication_confidence') AS FLOAT64) AS adj_confidence
             FROM pass_c_one AS p
             WHERE {adjudication_usable_sql('p')}),
     g AS (SELECT * FROM `{P}.{DS}.agreement`)
SELECT
  c.cve, c.osv_id, c.ecosystem, c.packages, c.summary, c.cvss,
  c.advisory_cwe, c.published, c.n_commits,
  c.repo_owner, c.repo_name, c.fix_sha, c.patch_sha256,
  c.candidate_fingerprint, c.patch_bytes,
  c.patch_format, c.patch_representation, c.patch_joiner,
  c.patch_max_bytes_per_commit, c.patch_truncated, c.patch_partial_fetch,
  c.patch_complete, c.patch_commits,
  -- Raw model labels are preserved for audit even when that model refused.
  -- relation/cwe_final below are populated only from usable analyses.
  g.cwe_pro, g.cwe_flash, g.relation, g.advisory_relation,
  -- adjudication layer (only present where the models genuinely diverged)
  adj.cwe_adjudicated, adj.adj_chose, adj.adj_rationale,
  adj.adj_both_defensible, adj.adj_confidence,
  -- score_agreement emits a single-model label only when that one analysis is
  -- usable.  It emits no final label when neither pass is usable.
  COALESCE(adj.cwe_adjudicated, g.cwe_final) AS cwe_final,
  CASE WHEN adj.cwe_adjudicated IS NOT NULL THEN 'adjudicated'
       WHEN g.cwe_final IS NOT NULL         THEN g.label_source
       WHEN g.label_source = 'needs_adjudication'
            THEN 'adjudication_missing'
       ELSE NULL END                        AS label_source,
  g.patch_sufficient_pro,
  -- Keep the old top-level name as a strict alias for Pro's explicit decision.
  -- New consumers should use the per-model and usability fields instead.
  COALESCE(g.analyzable_pro,
           SAFE_CAST(JSON_VALUE(a.analysis_pro,'$.analyzable') AS BOOL), FALSE)
      AS analyzable,
  COALESCE(g.analyzable_pro,
           SAFE_CAST(JSON_VALUE(a.analysis_pro,'$.analyzable') AS BOOL))
      AS analyzable_pro,
  COALESCE(g.analyzable_flash,
           SAFE_CAST(JSON_VALUE(b.analysis_flash,'$.analyzable') AS BOOL))
      AS analyzable_flash,
  COALESCE(g.usable_pro, FALSE) AS usable_pro,
  COALESCE(g.usable_flash, FALSE) AS usable_flash,
  COALESCE(g.crosscheck_usable, FALSE) AS crosscheck_usable,
  g.analysis_patch_sha256,
  g.analysis_candidate_fingerprint,
  g.pass_pro_record_sha256, g.pass_flash_record_sha256,
  g.analysis_pair_sha256,
  COALESCE(g.analysis_status, 'no_usable_analysis') AS analysis_status,
  COALESCE(g.pass_pro_present, a.cve IS NOT NULL) AS pass_pro_present,
  COALESCE(g.pass_flash_present, b.cve IS NOT NULL) AS pass_flash_present,
  (COALESCE(g.usable_pro, FALSE)
   AND COALESCE(JSON_VALUE(a.analysis_pro,'$.detection_heuristic'),'') != '')
      AS has_detection_heuristic,
  a.analysis_pro, b.analysis_flash,
  TRUE AS analysis_is_model_generated
FROM c
LEFT JOIN g   ON c.cve = g.cve
             AND c.patch_sha256 = g.analysis_patch_sha256
             AND c.candidate_fingerprint = g.analysis_candidate_fingerprint
LEFT JOIN a   ON c.cve = a.cve
             AND c.patch_sha256 = a.patch_sha256
             AND c.candidate_fingerprint = a.candidate_fingerprint
             AND g.pass_pro_record_sha256 = a.record_sha256
LEFT JOIN b   ON c.cve = b.cve
             AND c.patch_sha256 = b.patch_sha256
             AND c.candidate_fingerprint = b.candidate_fingerprint
             AND g.pass_flash_record_sha256 = b.record_sha256
LEFT JOIN adj ON c.cve = adj.cve
             AND c.patch_sha256 = adj.patch_sha256
             AND c.candidate_fingerprint = adj.candidate_fingerprint
             AND g.analysis_pair_sha256 = adj.analysis_pair_sha256
             AND g.crosscheck_usable IS TRUE
             AND g.label_source = 'needs_adjudication'
"""

def build_final():
    bq("query", "--use_legacy_sql=false", "--nouse_cache", FINAL_SQL)
    counts = json.loads(bq(
        "query", "--use_legacy_sql=false", "--format=json",
        f"SELECT COUNT(*) n, COUNT(DISTINCT cve) unique_cves "
        f"FROM `{P}.{DS}.dataset_final`"
    ))[0]
    n, unique_cves = int(counts["n"]), int(counts["unique_cves"])
    if n != unique_cves:
        raise RuntimeError(
            f"dataset_final contains {n} rows but only {unique_cves} unique CVEs"
        )
    print(f"  dataset_final: {n} rows")
    return n

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
