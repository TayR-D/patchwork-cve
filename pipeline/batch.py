#!/usr/bin/env python3
"""Patchwork Phase 2: Vertex batch-prediction harness.

gcloud has no `ai batch-prediction-jobs` surface in this SDK, so jobs go through
the REST API directly (same pattern used for the billing budget on day 1).

Stages: build -> submit -> poll -> harvest.
Rows are keyed by CVE, which is embedded in the prompt text, so output can be
re-associated even if batch does not preserve input order.
"""
import copy, hashlib, json, os, re, subprocess, sys, urllib.request, urllib.error, uuid

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, "pipeline"))
from analyze import build_request_body
import fetch_patches

PROJECT = os.environ.get("PW_PROJECT", "patchwork-cve-a1adb1")
REGION  = os.environ.get("PW_REGION", "us-central1")
BUCKET  = os.environ.get("PW_BUCKET", "gs://patchwork-cve-a1adb1-forge")
BASE    = f"https://{REGION}-aiplatform.googleapis.com/v1/projects/{PROJECT}/locations/{REGION}"

# Verified SKU rates, USD per 1M tokens (batch = 50% of on-demand)
RATES = {"gemini-2.5-pro":   {"batch": (0.625, 5.00), "ondemand": (1.25, 10.00)},
         "gemini-2.5-flash": {"batch": (0.15,  1.25), "ondemand": (0.30,  2.50)}}
THB_PER_USD = 34.5
ATTEMPT_RE = re.compile(r"[0-9a-f]{32}\Z")
SHARD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
REQUEST_PROVENANCE_RE = re.compile(
    r"\APATCHWORK_ATTEMPT: (?P<attempt>[0-9a-f]{32})\n"
    r"PATCHWORK_PATCH_SHA256: (?P<patch>[0-9a-f]{64})\n"
    r"PATCHWORK_CANDIDATE_SHA256: (?P<candidate>[0-9a-f]{64})\n"
    r"PATCHWORK_ANALYSIS_PAIR_SHA256: (?P<pair>[0-9a-f]{64}|none)\n"
    r"PATCHWORK_PRO_RECORD_SHA256: (?P<pro>[0-9a-f]{64}|none)\n"
    r"PATCHWORK_FLASH_RECORD_SHA256: (?P<flash>[0-9a-f]{64}|none)\n"
    r"PATCHWORK_INPUT_SHA256: (?P<input>[0-9a-f]{64})\n"
)


def verified_patch_path(row, statuses=None):
    """Return the canonical patch path only when provenance and bytes verify."""
    status_path = os.path.join(R, "out", "fetch_status.jsonl")
    statuses = (fetch_patches.load_latest_status(status_path)
                if statuses is None else statuses)
    cve = row.get("cve") if isinstance(row, dict) else None
    patch_dir = os.path.join(R, "out", "patches")
    if not isinstance(cve, str):
        return None
    status = statuses.get(cve, {})
    if not fetch_patches.status_matches_patch(status, row, patch_dir=patch_dir):
        return None
    return os.path.join(patch_dir, f"{cve}.patch")


def validate_shard(shard):
    if SHARD_RE.fullmatch(str(shard)) is None:
        raise ValueError(f"invalid shard id: {shard}")
    return str(shard)


def stable_sha256(value):
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def source_pair_sha256(cve, patch_sha256, candidate_sha256,
                       pro_record_sha256, flash_record_sha256):
    if not all((cve, patch_sha256, candidate_sha256,
                pro_record_sha256, flash_record_sha256)):
        return None
    return stable_sha256({
        "cve": cve,
        "patch_sha256": patch_sha256,
        "candidate_fingerprint": candidate_sha256,
        "pass_pro_record_sha256": pro_record_sha256,
        "pass_flash_record_sha256": flash_record_sha256,
    })


def attach_request_provenance(body, attempt_id, patch_sha256, candidate_sha256,
                              analysis_pair_sha256=None,
                              pass_pro_record_sha256=None,
                              pass_flash_record_sha256=None):
    """Embed immutable provenance in the request that Vertex echoes in output."""
    if ATTEMPT_RE.fullmatch(str(attempt_id)) is None:
        raise ValueError(f"invalid batch attempt id: {attempt_id}")
    if re.fullmatch(r"[0-9a-f]{64}", str(patch_sha256)) is None:
        raise ValueError("patch SHA-256 must be 64 lowercase hexadecimal characters")
    if re.fullmatch(r"[0-9a-f]{64}", str(candidate_sha256)) is None:
        raise ValueError("candidate SHA-256 must be 64 lowercase hexadecimal characters")
    pair_values = (analysis_pair_sha256, pass_pro_record_sha256,
                   pass_flash_record_sha256)
    if any(pair_values) and not all(
            re.fullmatch(r"[0-9a-f]{64}", str(value) or "")
            for value in pair_values):
        raise ValueError("Pass C provenance fingerprints must be supplied together")
    input_sha256 = stable_sha256(body)
    prompt = body["contents"][0]["parts"][0]["text"]
    body["contents"][0]["parts"][0]["text"] = (
        f"PATCHWORK_ATTEMPT: {attempt_id}\n"
        f"PATCHWORK_PATCH_SHA256: {patch_sha256}\n"
        f"PATCHWORK_CANDIDATE_SHA256: {candidate_sha256}\n"
        f"PATCHWORK_ANALYSIS_PAIR_SHA256: {analysis_pair_sha256 or 'none'}\n"
        f"PATCHWORK_PRO_RECORD_SHA256: {pass_pro_record_sha256 or 'none'}\n"
        f"PATCHWORK_FLASH_RECORD_SHA256: {pass_flash_record_sha256 or 'none'}\n"
        f"PATCHWORK_INPUT_SHA256: {input_sha256}\n"
        f"{prompt}"
    )
    return input_sha256


def verified_request_provenance(request_body, attempt_id):
    """Verify an echoed request and return its embedded immutable identifiers."""
    try:
        prompt = request_body["contents"][0]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError) as error:
        raise RuntimeError("batch output did not echo a recognizable request") from error
    match = REQUEST_PROVENANCE_RE.match(prompt or "")
    if not match or match.group("attempt") != attempt_id:
        raise RuntimeError("batch output request provenance is missing or from another attempt")
    unmarked = copy.deepcopy(request_body)
    unmarked["contents"][0]["parts"][0]["text"] = prompt[match.end():]
    if stable_sha256(unmarked) != match.group("input"):
        raise RuntimeError("batch output request body does not match its input hash")
    def optional_fingerprint(name):
        value = match.group(name)
        return None if value == "none" else value

    result = {
        "attempt_id": match.group("attempt"),
        "patch_sha256": match.group("patch"),
        "candidate_fingerprint": match.group("candidate"),
        "analysis_pair_sha256": optional_fingerprint("pair"),
        "pass_pro_record_sha256": optional_fingerprint("pro"),
        "pass_flash_record_sha256": optional_fingerprint("flash"),
        "input_sha256": match.group("input"),
        "prompt": prompt[match.end():],
    }
    pair_values = (result["analysis_pair_sha256"],
                   result["pass_pro_record_sha256"],
                   result["pass_flash_record_sha256"])
    if any(pair_values) and not all(pair_values):
        raise RuntimeError("batch output contains incomplete Pass C provenance")
    return result


def analysis_record_sha256(record):
    """Fingerprint one harvested response and all immutable input identifiers."""
    fields = {
        key: record.get(key)
        for key in (
            "cve", "model", "shard", "attempt_id", "patch_sha256",
            "candidate_fingerprint", "input_sha256", "analysis", "finish",
            "parse_error", "analysis_pair_sha256", "pass_pro_record_sha256",
            "pass_flash_record_sha256",
        )
    }
    return stable_sha256(fields)

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
    """Build/upload an immutable attempt; return path, kept, missing, attempt id."""
    shard = validate_shard(shard)
    attempt_id = uuid.uuid4().hex
    local = os.path.join(R, "out", "batch_in", f"{shard}.{attempt_id}.jsonl")
    os.makedirs(os.path.dirname(local), exist_ok=True)
    kept, missing = [], []
    status_path = os.path.join(R, "out", "fetch_status.jsonl")
    statuses = fetch_patches.load_latest_status(status_path)
    with open(local, "w") as fh:
        for row in rows:
            pf = verified_patch_path(row, statuses)
            if pf is None:
                missing.append(row["cve"]); continue
            patch_sha256 = fetch_patches.file_sha256(pf)
            candidate_sha256 = fetch_patches.candidate_fingerprint(row, patch_sha256)
            with open(pf, encoding="utf-8", errors="replace") as patch_file:
                patch_text = patch_file.read()
            body, meta = build_request_body(
                row, patch_text, thinking_budget=thinking, max_patch=max_patch,
                max_output=max_output
            )
            input_sha256 = attach_request_provenance(
                body, attempt_id, patch_sha256, candidate_sha256
            )
            fh.write(json.dumps({"request": body}) + "\n")
            kept.append({"cve": row["cve"], "patch_sha256": patch_sha256,
                         "candidate_fingerprint": candidate_sha256,
                         "input_sha256": input_sha256, **meta})
    input_uri = f"{BUCKET}/batch_in/{shard}/{attempt_id}.jsonl"
    gs("cp", local, input_uri)
    idx = os.path.join(R, "out", "batch_in", f"{shard}.{attempt_id}.index.json")
    with open(idx, "w") as index_file:
        json.dump({"shard": shard, "attempt_id": attempt_id, "model": model,
                   "thinking": thinking, "input_uri": input_uri,
                   "rows": kept, "missing": missing}, index_file)
    return local, len(kept), len(missing), attempt_id

# ---------------------------------------------------------------- submit
def submit(shard, model, attempt_id, tok=None):
    shard = validate_shard(shard)
    if ATTEMPT_RE.fullmatch(str(attempt_id)) is None:
        raise ValueError(f"invalid batch attempt id: {attempt_id}")
    body = {
        "displayName": f"pw-{shard}-{attempt_id[:12]}",
        "model": f"publishers/google/models/{model}",
        "inputConfig": {"instancesFormat": "jsonl",
                        "gcsSource": {"uris": [
                            f"{BUCKET}/batch_in/{shard}/{attempt_id}.jsonl"
                        ]}},
        "outputConfig": {"predictionsFormat": "jsonl",
                         "gcsDestination": {"outputUriPrefix":
                             f"{BUCKET}/batch_out/{shard}/{attempt_id}/"}},
    }
    return api("POST", f"{BASE}/batchPredictionJobs", body, tok)

def get_job(name, tok=None):
    return api("GET", f"https://{REGION}-aiplatform.googleapis.com/v1/{name}", None, tok)

# ---------------------------------------------------------------- harvest
CVE_RE = re.compile(r"^CVE:\s*(CVE-[\d-]+)", re.M)

def harvest(shard, model, attempt_id, mode="batch"):
    """Read batch output from GCS, return per-row records + cost accounting."""
    try:
        shard = validate_shard(shard)
    except ValueError as error:
        raise RuntimeError(str(error)) from error
    if ATTEMPT_RE.fullmatch(str(attempt_id)) is None:
        raise RuntimeError(f"missing or invalid attempt id for shard {shard}")
    index_path = os.path.join(
        R, "out", "batch_in", f"{shard}.{attempt_id}.index.json"
    )
    try:
        with open(index_path, encoding="utf-8") as index_file:
            index = json.load(index_file)
    except (FileNotFoundError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"missing or invalid batch index {index_path}; cannot bind outputs to patch bytes"
        ) from error
    if (index.get("shard") != shard or index.get("model") != model
            or index.get("attempt_id") != attempt_id):
        raise RuntimeError("batch index identity does not match the requested harvest")
    index_rows = index.get("rows", [])
    index_by_cve = {row.get("cve"): row for row in index_rows if row.get("cve")}
    listing = gs("ls", f"{BUCKET}/batch_out/{shard}/{attempt_id}/**")
    files = [l.strip() for l in listing.splitlines()
             if l.strip().endswith(".jsonl") and "prediction" in l]
    recs, errs = [], []
    tin = tout = 0
    for f in files:
        for line_number, line in enumerate(gs("cat", f).splitlines(), 1):
            if not line.strip(): continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError as error:
                raise RuntimeError(
                    f"invalid batch output JSON in {f} line {line_number}: {error.msg}"
                ) from error
            provenance = verified_request_provenance(d.get("request"), attempt_id)
            m = CVE_RE.search(provenance["prompt"])
            cve = m.group(1) if m else None
            indexed = index_by_cve.get(cve)
            if not indexed:
                raise RuntimeError(f"batch output contains unindexed CVE: {cve}")
            if (indexed.get("patch_sha256") != provenance["patch_sha256"]
                    or indexed.get("candidate_fingerprint")
                    != provenance["candidate_fingerprint"]
                    or indexed.get("input_sha256") != provenance["input_sha256"]):
                raise RuntimeError(f"batch output provenance mismatch for {cve}")
            embedded_pair = source_pair_sha256(
                cve, provenance["patch_sha256"],
                provenance["candidate_fingerprint"],
                provenance["pass_pro_record_sha256"],
                provenance["pass_flash_record_sha256"],
            )
            if embedded_pair != provenance["analysis_pair_sha256"]:
                raise RuntimeError(f"invalid embedded analysis-pair fingerprint for {cve}")
            for field in ("analysis_pair_sha256", "pass_pro_record_sha256",
                          "pass_flash_record_sha256"):
                if indexed.get(field) != provenance[field]:
                    raise RuntimeError(f"batch output {field} mismatch for {cve}")
            patch_sha256 = provenance["patch_sha256"]
            if d.get("status") or "response" not in d:
                errs.append({"cve": cve, "attempt_id": attempt_id,
                             "patch_sha256": patch_sha256,
                             "candidate_fingerprint": provenance["candidate_fingerprint"],
                             "input_sha256": provenance["input_sha256"],
                             "error": str(d.get("status"))[:300]}); continue
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
            record = {"cve": cve, "model": model, "shard": shard,
                      "attempt_id": attempt_id, "patch_sha256": patch_sha256,
                      "candidate_fingerprint": provenance["candidate_fingerprint"],
                      "input_sha256": provenance["input_sha256"],
                      "analysis": analysis, "finish": cand.get("finishReason"),
                      "parse_error": perr, "tokens_in": ti, "tokens_out": to}
            for field in ("analysis_pair_sha256", "pass_pro_record_sha256",
                          "pass_flash_record_sha256"):
                if provenance[field]:
                    record[field] = provenance[field]
            record["record_sha256"] = analysis_record_sha256(record)
            recs.append(record)
    ri, ro = RATES[model][mode]
    usd = (tin*ri + tout*ro)/1e6
    return recs, errs, {"tokens_in": tin, "tokens_out": tout,
                        "usd": round(usd,4), "thb": round(usd*THB_PER_USD,2)}

if __name__ == "__main__":
    print("module; use via smoke/run scripts")
