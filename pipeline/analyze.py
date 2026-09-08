#!/usr/bin/env python3
"""Patchwork: Gemini analysis of a CVE fix commit."""
import json, os, re, subprocess, urllib.request, urllib.error

PROJECT = os.environ.get("PW_PROJECT", "patchwork-cve-a1adb1")
REGION  = os.environ.get("PW_REGION", "us-central1")
MAX_PATCH_BYTES = int(os.environ.get("PW_MAX_PATCH", "48000"))

SKIP_PATH = re.compile(r"(package-lock\.json|yarn\.lock|go\.sum|Cargo\.lock|composer\.lock"
                       r"|\.min\.(js|css)$|/vendor/|/node_modules/|/testdata/|\.(png|jpg|gif|svg|pdf|zip)$)", re.I)

def token():
    return subprocess.run(["gcloud","auth","print-access-token"],capture_output=True,text=True,timeout=60).stdout.strip()

def fetch_patch(owner, repo, sha, timeout=45):
    url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
    req = urllib.request.Request(url, headers={"User-Agent":"patchwork-research/0.1"})
    return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8","replace")

def split_files(patch):
    """Split a git patch into per-file chunks."""
    parts = re.split(r"(?m)^(?=diff --git )", patch)
    return [p for p in parts if p.strip()]

def trim_patch(patch, budget=MAX_PATCH_BYTES):
    """Keep the most security-relevant files within a byte budget.

    Lockfiles, vendored trees and binaries are dropped first; remaining files are
    taken smallest-first so a single huge file cannot crowd out the rest.
    """
    chunks = split_files(patch)
    if not chunks: return patch[:budget], 0, 0
    keep, dropped = [], 0
    for c in chunks:
        m = re.match(r"diff --git a/(\S+)", c)
        path = m.group(1) if m else ""
        if SKIP_PATH.search(path): dropped += 1; continue
        keep.append((len(c), path, c))
    if not keep:
        keep = [(len(c), "", c) for c in chunks]
    keep.sort(key=lambda t: t[0])
    out, used, truncated = [], 0, 0
    for size, path, c in keep:
        if used + size > budget:
            room = budget - used
            if room > 2000:
                out.append(c[:room] + "\n... [file truncated]\n"); used = budget
            truncated += 1
            continue
        out.append(c); used += size
    return "".join(out), dropped, truncated

SCHEMA = {
  "type":"object",
  "properties":{
    "analyzable":{"type":"boolean"},
    "unanalyzable_reason":{"type":"string"},
    # Vertex responseSchema supports nullable fields, but not JSON Schema
    # conditionals (if/then).  A refusal must therefore be allowed to carry no
    # CWE here and is validated against ``analyzable`` again downstream.
    "cwe_primary":{"type":"string", "nullable":True},
    "cwe_secondary":{"type":"array","items":{"type":"string"}},
    "cwe_confidence":{"type":"number"},
    "vulnerability_class":{"type":"string"},
    "root_cause":{"type":"string"},
    "taint_source":{"type":"string"},
    "taint_sink":{"type":"string"},
    "taint_path":{"type":"array","items":{"type":"string"}},
    "trigger_condition":{"type":"string"},
    "patch_mechanism":{"type":"string"},
    "patch_sufficient":{"type":"boolean"},
    "patch_reasoning":{"type":"string"},
    "residual_risk":{"type":"string"},
    "detection_heuristic":{"type":"string"},
    "detection_kind":{"type":"string","enum":["dataflow","syntactic","semantic","config","none"]},
    "false_positive_risk":{"type":"string","enum":["low","medium","high"]},
    "affected_functions":{"type":"array","items":{"type":"string"}},
    "exploit_preconditions":{"type":"array","items":{"type":"string"}},
    "confidence_overall":{"type":"number"}
  },
  "required":["analyzable","cwe_confidence","vulnerability_class","root_cause",
              "patch_mechanism","patch_sufficient","patch_reasoning","detection_heuristic",
              "detection_kind","false_positive_risk","confidence_overall"]
}

PROMPT = """You are analysing a PUBLIC, ALREADY-PATCHED software vulnerability for a defensive security research dataset. The goal is to help build better vulnerability *detectors*. Do not write exploit code.

Analyse the vulnerability that the commit below FIXES.

Ground every claim in the diff. Where the advisory text and the diff disagree, trust the diff. If the diff does not actually contain enough information to identify the vulnerability (for example it is only a version bump, a docs change, or the relevant code is not shown), set analyzable=false, set cwe_primary=null, and explain why in unanalyzable_reason -- do not guess. An honest refusal is far more valuable to this dataset than a plausible fabrication.

Only when analyzable=true, assign cwe_primary as a specific CWE identifier such as "CWE-89". Set cwe_confidence and confidence_overall to your genuine calibrated confidence in [0,1], not a default value.

detection_heuristic must describe what a static or dynamic analyser should look for to catch this class of bug in other code -- not merely a restatement of this specific fix.

=== ADVISORY ===
CVE: {cve}
Ecosystem: {eco}   Packages: {pkgs}
CVSS: {cvss}
Advisory CWE (may be wrong or absent; form your own judgement): {cwe}
Summary: {summary}
Details:
{details}

=== FIX COMMIT {owner}/{repo}@{sha} ===
{patch}
=== END ===
"""

def build_prompt(row, patch_text, max_patch=None):
    """Render the analysis prompt. Shared by on-demand and batch paths."""
    patch, dropped, truncated = trim_patch(patch_text, max_patch or MAX_PATCH_BYTES)
    c = row["commits"][0]
    prompt = PROMPT.format(
        cve=row["cve"], eco=row["ecosystem"], pkgs=", ".join(row["packages"]) or "n/a",
        cvss=row.get("cvss") or "n/a", cwe=", ".join(row.get("cwe_ids") or []) or "none",
        summary=row.get("summary") or "n/a", details=(row.get("details") or "n/a")[:3000],
        owner=c["owner"], repo=c["repo"], sha=c["sha"][:12], patch=patch)
    return prompt, {"patch_bytes": len(patch), "files_dropped": dropped, "files_truncated": truncated}


def build_request_body(row, patch_text, thinking_budget=None, max_patch=None, max_output=8192):
    """The exact request body used for BOTH on-demand and batch prediction."""
    prompt, meta = build_prompt(row, patch_text, max_patch)
    gc = {"temperature": 0.1, "maxOutputTokens": max_output,
          "responseMimeType": "application/json", "responseSchema": SCHEMA}
    if thinking_budget is not None:
        gc["thinkingConfig"] = {"thinkingBudget": thinking_budget}
    return {"contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": gc}, meta


def analyze(row, model="gemini-2.5-pro", tok=None, thinking_budget=None, max_patch=None,
            patch_text=None, max_output=8192):
    c = row["commits"][0]
    if patch_text is None:
        patch_text = fetch_patch(c["owner"], c["repo"], c["sha"])
    body, meta = build_request_body(row, patch_text, thinking_budget, max_patch, max_output)
    url = (f"https://{REGION}-aiplatform.googleapis.com/v1/projects/{PROJECT}"
           f"/locations/{REGION}/publishers/google/models/{model}:generateContent")
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
    resp = json.load(urllib.request.urlopen(req, timeout=300))
    um = resp.get("usageMetadata", {})
    cand = (resp.get("candidates") or [{}])[0]
    parts = (cand.get("content") or {}).get("parts") or []
    txt = "".join(p.get("text", "") for p in parts)
    return {
        "cve": row["cve"], "model": model,
        "analysis": json.loads(txt) if txt.strip() else None,
        "finish": cand.get("finishReason"),
        "tokens_in": um.get("promptTokenCount", 0),
        "tokens_out": um.get("candidatesTokenCount", 0),
        "tokens_thought": um.get("thoughtsTokenCount", 0),
        "patch_bytes": meta["patch_bytes"], "files_dropped": meta["files_dropped"],
        "files_truncated": meta["files_truncated"],
        "advisory_cwe": row.get("cwe_ids") or [],
    }
