#!/usr/bin/env python3
"""Patchwork: build the CVE-fix candidate index from OSV bulk data.

Emits one JSONL row per (CVE, fix-commit) candidate. No inference happens here,
so this stage is free and runs before any credit is spent. The default OSV bulk
feed is live; preserve the downloaded ZIPs when an exactly repeatable source
snapshot is required.
"""
import zipfile, json, re, os, sys, collections, urllib.request

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OSV = "https://osv-vulnerabilities.storage.googleapis.com"
ECOS = ["Go","crates.io","npm","PyPI","Maven","Packagist","RubyGems","NuGet",
        "Hex","Pub","Hackage","CRAN","GitHub Actions","Linux","GIT"]
CRE = re.compile(r"https?://github\.com/([^/\s]+)/([^/\s]+)/commit/([0-9a-f]{7,40})")
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")

def cache_dir():
    d = os.environ.get("PW_CACHE", "/tmp/pw_osv"); os.makedirs(d, exist_ok=True); return d

def fetch(eco):
    f = os.path.join(cache_dir(), re.sub(r"[^A-Za-z0-9]", "", eco) + ".zip")
    if os.path.exists(f) and os.path.getsize(f) > 1000:
        return f
    url = f"{OSV}/{urllib.parse.quote(eco)}/all.zip"
    try:
        urllib.request.urlretrieve(url, f)
    except Exception as e:
        print(f"  ! {eco}: {e}", file=sys.stderr); return None
    return f

def cvss_of(d):
    for s in d.get("severity", []) or []:
        if s.get("type","").startswith("CVSS"): return s.get("score")
    for aff in d.get("affected", []):
        for s in (aff.get("severity") or []):
            if s.get("type","").startswith("CVSS"): return s.get("score")
    return None

def extract(eco, zf):
    z = zipfile.ZipFile(zf); out = []
    for n in z.namelist():
        if not n.endswith(".json"): continue
        try: d = json.loads(z.read(n))
        except Exception: continue
        if d.get("withdrawn"): continue
        cves = sorted(a for a in d.get("aliases", []) if CVE_RE.fullmatch(a))
        if not cves: continue
        commits, seen = [], set()
        for r in d.get("references", []) or []:
            m = CRE.match((r.get("url") or "").strip())
            if not m: continue
            owner, repo, sha = m.group(1), m.group(2).removesuffix(".git"), m.group(3)
            key = (owner.lower(), repo.lower(), sha[:7])
            if key in seen: continue
            seen.add(key)
            commits.append({"owner": owner, "repo": repo, "sha": sha, "ref_type": r.get("type")})
        # GIT-range fixed events (Linux kernel and OSS-Fuzz use these)
        for aff in d.get("affected", []) or []:
            for rng in aff.get("ranges", []) or []:
                if rng.get("type") != "GIT": continue
                m = re.match(r"https?://github\.com/([^/\s]+)/([^/\s]+)", rng.get("repo",""))
                if not m: continue
                for ev in rng.get("events", []) or []:
                    sha = ev.get("fixed")
                    if not sha: continue
                    owner, repo = m.group(1), m.group(2).removesuffix(".git")
                    key = (owner.lower(), repo.lower(), sha[:7])
                    if key in seen: continue
                    seen.add(key)
                    commits.append({"owner": owner, "repo": repo, "sha": sha, "ref_type": "GIT_RANGE"})
        if not commits: continue
        pkgs = sorted({(a.get("package") or {}).get("name","") for a in d.get("affected",[]) if a.get("package")})
        ds = d.get("database_specific") or {}
        out.append({
            "osv_id": d["id"], "cve": cves[0], "all_cves": cves, "ecosystem": eco,
            "packages": [p for p in pkgs if p][:5],
            "summary": (d.get("summary") or "")[:400],
            "details": (d.get("details") or "")[:4000],
            "cvss": cvss_of(d),
            "cwe_ids": ds.get("cwe_ids") or [],
            "severity_label": ds.get("severity"),
            "published": d.get("published"), "modified": d.get("modified"),
            "commits": commits, "n_commits": len(commits),
        })
    return out

def main():
    rows, st = [], collections.Counter()
    for eco in ECOS:
        zf = fetch(eco)
        if not zf: continue
        r = extract(eco, zf)
        st[eco] = len(r); rows.extend(r)
        print(f"  {eco:<16} {len(r):>6} candidates", flush=True)
    # dedupe on CVE, preferring the record with a single commit and richer detail
    best = {}
    for r in rows:
        k = r["cve"]
        cur = best.get(k)
        score = (r["n_commits"] == 1, len(r["details"]), bool(r["cwe_ids"]))
        if cur is None or score > cur[0]:
            best[k] = (score, r)
    final = [v[1] for v in best.values()]
    final.sort(key=lambda r: r["cve"])
    out = os.environ.get("PW_OUT", os.path.join(R, "out", "candidates.jsonl"))
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w") as fh:
        for r in final: fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"\n  raw rows        {len(rows)}")
    print(f"  unique CVEs     {len(final)}")
    print(f"  single-commit   {sum(1 for r in final if r['n_commits']==1)}")
    print(f"  with CWE label  {sum(1 for r in final if r['cwe_ids'])}")
    print(f"  with CVSS       {sum(1 for r in final if r['cvss'])}")
    print(f"  -> {out}")

if __name__ == "__main__":
    import urllib.parse; main()
