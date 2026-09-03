#!/usr/bin/env python3
"""Add duplicate-group marking and a leakage-free benchmark split.

662 patch hashes are shared by more than one CVE (a single commit often fixes
several advisories). Those rows are real and are kept -- but a naive random split
would put the same diff in train and eval, so the split is made GROUP-AWARE:
every CVE sharing a patch hash lands on the same side.
"""
import json, os, subprocess, sys, hashlib, collections
R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, "scripts"))
import batch
P = batch.PROJECT

SQL = f"""
CREATE OR REPLACE TABLE `{P}.patchwork.dataset_final` AS
WITH base AS (SELECT * FROM `{P}.patchwork.dataset_final`),
     grp  AS (SELECT patch_sha256, COUNT(*) AS dup_group_size
              FROM base GROUP BY 1)
SELECT b.*,
       g.dup_group_size,
       -- group-aware, deterministic: the whole hash-group shares one bucket, so a
       -- diff can never appear on both sides of the split
       CASE WHEN MOD(ABS(FARM_FINGERPRINT(b.patch_sha256)), 100) < 9
            THEN 'eval' ELSE 'train' END AS split
FROM base b JOIN grp g USING (patch_sha256)
"""

def bq(*a, timeout=1800):
    cp = subprocess.run(["bq","--project_id="+P,*a], capture_output=True, text=True, timeout=timeout)
    if cp.returncode != 0:
        raise RuntimeError(((cp.stderr or "")+(cp.stdout or ""))[:500])
    return cp.stdout

if __name__ == "__main__":
    bq("query","--use_legacy_sql=false","--nouse_cache", SQL)
    out = bq("query","--use_legacy_sql=false","--format=json",
             f"""SELECT split, COUNT(*) n, COUNT(DISTINCT patch_sha256) uniq_patches,
                        COUNTIF(dup_group_size>1) in_dup_group
                 FROM `{P}.patchwork.dataset_final` GROUP BY 1 ORDER BY 1""")
    for r in json.loads(out):
        print(f"  {r['split']:<6} rows={int(r['n']):>6,}  unique_patches={int(r['uniq_patches']):>6,}"
              f"  in_dup_group={int(r['in_dup_group']):>5,}")
    # leakage assertion: no patch hash may appear in both splits
    leak = json.loads(bq("query","--use_legacy_sql=false","--format=json",
        f"""SELECT COUNT(*) n FROM (
              SELECT patch_sha256 FROM `{P}.patchwork.dataset_final`
              GROUP BY 1 HAVING COUNT(DISTINCT split) > 1)"""))[0]["n"]
    print(f"\n  LEAKAGE CHECK: {leak} patch hashes span both splits " + ("OK" if int(leak)==0 else "<<< FAIL"))
