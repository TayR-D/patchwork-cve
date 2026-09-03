#!/usr/bin/env python3
"""Pass C: adjudicate rows where the two models disagree beyond the hierarchy.

Candidates are rows whose Pro/Flash CWE relation is `sibling` or `conflict`.
The two candidate analyses are presented ANONYMOUSLY ("Analysis 1" / "Analysis 2",
order randomised per row) so the adjudicator cannot defer to the stronger model
by reputation -- it has to argue from the diff.
"""
import json, os, random, hashlib

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ADJ_SCHEMA = {
  "type": "object",
  "properties": {
    "cwe_final": {"type": "string"},
    "chose": {"type": "string", "enum": ["analysis_1", "analysis_2", "neither"]},
    "rationale": {"type": "string"},
    "both_defensible": {"type": "boolean"},
    "adjudication_confidence": {"type": "number"},
    "root_cause_final": {"type": "string"},
    "patch_sufficient_final": {"type": "boolean"},
  },
  "required": ["cwe_final","chose","rationale","both_defensible","adjudication_confidence"],
}

ADJ_PROMPT = """You are adjudicating a disagreement between two independent analyses of the SAME public, already-patched vulnerability, for a defensive security research dataset.

Two analysts assigned different CWE identifiers. Decide which is better supported BY THE DIFF, or supply a third CWE if both are wrong.

Judge only on evidence in the code. The two analyses are unlabelled and presented in arbitrary order -- there is no "senior" analyst here, and you must not prefer one because it is longer or more confident. If both are defensible descriptions at different levels of abstraction, set both_defensible=true and choose the one that most precisely names the mechanism the patch actually changes.

Set adjudication_confidence to genuine calibrated confidence in [0,1].

=== ADVISORY ===
CVE: {cve}
Advisory CWE (may itself be wrong or coarse): {adv}
Summary: {summary}

=== ANALYSIS 1 ===
CWE: {cwe1}
class: {class1}
root cause: {rc1}
patch reasoning: {pr1}

=== ANALYSIS 2 ===
CWE: {cwe2}
class: {class2}
root cause: {rc2}
patch reasoning: {pr2}

=== FIX COMMIT {owner}/{repo}@{sha} ===
{patch}
=== END ===
"""

def build_adj_request(row, pro, flash, patch_text, thinking=1024, max_patch=32000):
    """Anonymise + randomise the two analyses, then build the request body."""
    import sys; sys.path.insert(0, os.path.join(R, "scripts"))
    from analyze import trim_patch
    patch, _, _ = trim_patch(patch_text, max_patch)
    # deterministic per-CVE ordering so re-runs are reproducible
    flip = int(hashlib.md5(row["cve"].encode()).hexdigest(), 16) % 2 == 1
    a, b = (flash, pro) if flip else (pro, flash)
    c = row["commits"][0]
    prompt = ADJ_PROMPT.format(
        cve=row["cve"], adv=", ".join(row.get("cwe_ids") or []) or "none",
        summary=(row.get("summary") or "n/a")[:300],
        cwe1=a.get("cwe_primary"), class1=a.get("vulnerability_class"),
        rc1=(a.get("root_cause") or "")[:600], pr1=(a.get("patch_reasoning") or "")[:400],
        cwe2=b.get("cwe_primary"), class2=b.get("vulnerability_class"),
        rc2=(b.get("root_cause") or "")[:600], pr2=(b.get("patch_reasoning") or "")[:400],
        owner=c["owner"], repo=c["repo"], sha=c["sha"][:12], patch=patch)
    body = {"contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": 4096,
                                 "responseMimeType": "application/json",
                                 "responseSchema": ADJ_SCHEMA,
                                 "thinkingConfig": {"thinkingBudget": thinking}}}
    # map back: which slot held which model
    slots = {"analysis_1": "flash" if flip else "pro", "analysis_2": "pro" if flip else "flash"}
    return body, slots

if __name__ == "__main__":
    print("adjudication schema fields:", list(ADJ_SCHEMA["properties"]))
