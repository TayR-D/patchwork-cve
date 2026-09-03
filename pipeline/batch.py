#!/usr/bin/env python3
"""Patchwork Phase 2: Vertex batch-prediction harness.

gcloud has no `ai batch-prediction-jobs` surface in this SDK, so jobs go through
the REST API directly (same pattern used for the billing budget on day 1).

Stages: build -> submit -> poll -> harvest.
Rows are keyed by CVE, which is embedded in the prompt text, so output can be
re-associated even if batch does not preserve input order.
"""
import json, os, re, subprocess, sys, time, urllib.request, urllib.error

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, "scripts"))
from analyze import build_request_body

PROJECT = os.environ.get("PW_PROJECT", "patchwork-cve-a1adb1")
REGION  = os.environ.get("PW_REGION", "us-central1")
BUCKET  = os.environ.get("PW_BUCKET", "gs://patchwork-cve-a1adb1-forge")
BASE    = f"https://{REGION}-aiplatform.googleapis.com/v1/projects/{PROJECT}/locations/{REGION}"

# Verified SKU rates, USD per 1M tokens (batch = 50% of on-demand)
RATES = {"gemini-2.5-pro":   {"batch": (0.625, 5.00), "ondemand": (1.25, 10.00)},
         "gemini-2.5-flash": {"batch": (0.15,  1.25), "ondemand": (0.30,  2.50)}}
THB_PER_USD = 34.5

def token():
    return subprocess.run(["gcloud","auth","print-access-token"],
                          capture_output=True, text=True, timeout=60).stdout.strip()

def api(method, url, body=None, tok=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
            headers={"Authorization": f"Bearer {tok or token()}",
                     "Content-Type": "application/json",
                     "x-goog-user-project": PROJECT})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.read().decode()[:900]}") from None

def gs(*args, check=True, capture=True):
    cp = subprocess.run(["gcloud","storage",*args], capture_output=capture, text=True, timeout=900)
    if check and cp.returncode != 0:
        raise RuntimeError(f"gcloud storage {args[0]} failed: {cp.stderr[:400]}")
    return cp.stdout

# ---------------------------------------------------------------- build
def build(rows, shard, model, thinking, max_patch=32000, max_output=8192):
    """Write a batch input JSONL locally and upload it. Returns (path, kept, missing)."""
    local = os.path.join(R, "out", "batch_in", f"{shard}.jsonl")
    os.makedirs(os.path.dirname(local), exist_ok=True)
    kept, missing = [], []
    with open(local, "w") as fh:
        for row in rows:
            pf = os.path.join(R, "out", "patches", f"{row['cve']}.patch")
            if not os.path.exists(pf):
                missing.append(row["cve"]); continue
            body, meta = build_request_body(row, open(pf, encoding="utf-8", errors="replace").read(),
                                            thinking_budget=thinking, max_patch=max_patch,
                                            max_output=max_output)
            fh.write(json.dumps({"request": body}) + "\n")
            kept.append({"cve": row["cve"], **meta})
    gs("cp", local, f"{BUCKET}/batch_in/{shard}.jsonl")
    idx = os.path.join(R, "out", "batch_in", f"{shard}.index.json")
    json.dump({"shard": shard, "model": model, "thinking": thinking,
               "rows": kept, "missing": missing}, open(idx, "w"))
    return local, len(kept), len(missing)

# ---------------------------------------------------------------- submit
def submit(shard, model, tok=None):
    body = {
        "displayName": f"pw-{shard}",
        "model": f"publishers/google/models/{model}",
        "inputConfig": {"instancesFormat": "jsonl",
                        "gcsSource": {"uris": [f"{BUCKET}/batch_in/{shard}.jsonl"]}},
        "outputConfig": {"predictionsFormat": "jsonl",
                         "gcsDestination": {"outputUriPrefix": f"{BUCKET}/batch_out/{shard}/"}},
    }
    return api("POST", f"{BASE}/batchPredictionJobs", body, tok)

def get_job(name, tok=None):
    return api("GET", f"https://{REGION}-aiplatform.googleapis.com/v1/{name}", None, tok)

# ---------------------------------------------------------------- harvest
CVE_RE = re.compile(r"^CVE:\s*(CVE-[\d-]+)", re.M)

def harvest(shard, model, mode="batch"):
    """Read batch output from GCS, return per-row records + cost accounting."""
    listing = gs("ls", f"{BUCKET}/batch_out/{shard}/**")
    files = [l.strip() for l in listing.splitlines()
             if l.strip().endswith(".jsonl") and "prediction" in l]
    recs, errs = [], []
    tin = tout = 0
    for f in files:
        for line in gs("cat", f).splitlines():
            if not line.strip(): continue
            try: d = json.loads(line)
            except Exception: continue
            req_text = ""
            try:
                req_text = d["request"]["contents"][0]["parts"][0]["text"]
            except Exception: pass
            m = CVE_RE.search(req_text or "")
            cve = m.group(1) if m else None
            if d.get("status") or "response" not in d:
                errs.append({"cve": cve, "error": str(d.get("status"))[:300]}); continue
            resp = d["response"]
            um = resp.get("usageMetadata", {})
            cand = (resp.get("candidates") or [{}])[0]
            parts = (cand.get("content") or {}).get("parts") or []
            txt = "".join(p.get("text","") for p in parts)
            analysis, perr = None, None
            if txt.strip():
                try: analysis = json.loads(txt)
                except Exception as e: perr = f"parse:{type(e).__name__}"
            ti = um.get("promptTokenCount",0)
            to = um.get("candidatesTokenCount",0) + um.get("thoughtsTokenCount",0)
            tin += ti; tout += to
            recs.append({"cve": cve, "model": model, "shard": shard,
                         "analysis": analysis, "finish": cand.get("finishReason"),
                         "parse_error": perr, "tokens_in": ti, "tokens_out": to})
    ri, ro = RATES[model][mode]
    usd = (tin*ri + tout*ro)/1e6
    return recs, errs, {"tokens_in": tin, "tokens_out": tout,
                        "usd": round(usd,4), "thb": round(usd*THB_PER_USD,2)}

if __name__ == "__main__":
    print("module; use via smoke/run scripts")
