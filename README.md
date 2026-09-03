# Patchwork — CVE vulnerability dataset with CWE labels and root-cause analysis

**16,597 real, already-patched CVEs, each with its fix commit and a structured analysis of the
vulnerability — root cause, taint path, why the patch works, and a proposed detection heuristic.**

`security dataset` · `vulnerability detection` · `CVE` · `CWE classification` · `patch analysis` ·
`static analysis training data` · `security machine learning` · `taint analysis` · `AppSec benchmark`

| | |
|---|---|
| **Rows** | 16,597 CVEs |
| **Ecosystems** | PyPI, npm, Maven, Packagist, Go, RubyGems, NuGet, crates.io, Hex, and more |
| **Years covered** | 2010–2026 |
| **Distinct CWEs** | ~300 |
| **Split** | 15,107 train / 1,490 eval (group-aware, leakage-verified) |
| **Formats** | Parquet (46 MB), JSONL.gz (28 MB) |
| **Licence** | CC-BY-4.0 (data), MIT (code) |

Public vulnerability datasets (BigVul, CVEfixes, DiverseVul) label a function as vulnerable, assign a
CWE, and stop. What they omit is the reasoning: which input reaches the sink, why the patch closes the
path, and what a detector should key on. That absence is a large part of why detectors overfit to
surface syntax. Patchwork adds that layer.

## How this compares to other vulnerability datasets

| dataset | rows | CWE labels | root-cause reasoning | detection heuristics | cross-checked labels |
|---|---:|:---:|:---:|:---:|:---:|
| BigVul | ~188k functions | yes | no | no | no |
| CVEfixes | ~5k CVEs | yes | no | no | no |
| DiverseVul | ~349k functions | yes | no | no | no |
| **Patchwork** | **16,597 CVEs** | **yes** | **yes** | **yes** | **yes (2 models + blind adjudication)** |

Patchwork is smaller than function-level corpora by design: it trades row count for depth per row.
Each entry explains *why* the code was vulnerable and *what a detector should look for*, rather than
only marking a function vulnerable.

## Get the data

Download from the [latest release](../../releases/latest):

| file | size | notes |
|---|---:|---|
| `patchwork-cve.parquet` | 46 MB | primary format |
| `patchwork-cve.jsonl.gz` | 28 MB | dependency-free |

```python
import pandas as pd
df = pd.read_parquet("patchwork-cve.parquet")

# IMPORTANT: filter refusals before trusting the label -- see below
usable = df[df.analyzable]
```

## Read this before using `cwe_final`

`cwe_primary` was a **required** field in the analysis schema. When the model set `analyzable=false`
— honestly declining a diff it could not interpret — the schema still forced it to emit a CWE.
**692 rows (4.2%) carry a label the model itself disclaimed.** They are retained rather than nulled
because they may still carry signal, but they are not cross-check-backed.

**Always filter on `analyzable` before treating `cwe_final` as a label.**

## How the labels were made

Two models analyse each diff **independently**. Confidence is their agreement scored against the
MITRE CWE hierarchy — not any model's self-reported confidence, which measured a useless 0.94 mean
in piloting while returning 1.0 on a case where it gave three different answers across three runs.

Ancestor/descendant CWE pairs count as compatible (the more specific label wins). Siblings and
unrelated pairs go to a third adjudication pass that sees both analyses **anonymised and
order-randomised**, so it cannot defer to the better-known model by reputation.

| label_source | rows | share |
|---|---:|---:|
| `agreement` — both models chose the same CWE | 11,485 | 69.2% |
| `adjudicated` — models disagreed, resolved blind | 3,450 | 20.8% |
| `agreement_specific` — hierarchy-compatible | 1,640 | 9.9% |
| `single_model_unverified` — no cross-check available | 22 | 0.13% |

**Disagreement is preserved on every row.** `cwe_pro`, `cwe_flash` and `relation` are always present,
so you can re-derive or override any label decision.

### Did the second model earn its cost?

3,450 disagreements were adjudicated blind. Decoding which model held each anonymous slot:

| outcome | share |
|---|---:|
| Pro's label preferred | 63.7% |
| Flash's label preferred | 24.2% |
| neither — adjudicator supplied a third CWE | 12.1% |

A single-model corpus would carry the wrong primary CWE on roughly **36% of disagreement rows**.
Position bias check: slot 1 chosen 44.8% vs slot 2 43.2%, so the adjudicator judged on evidence
rather than position.

## Schema

| column | type | description |
|---|---|---|
| `cve` | string | CVE identifier, e.g. `CVE-2021-44228` |
| `osv_id` | string | OSV/GHSA advisory id |
| `ecosystem` | string | package ecosystem (PyPI, npm, Maven, Go, …) |
| `packages` | list | affected package names |
| `summary` | string | advisory summary |
| `cvss` | string | CVSS v3 vector, where published |
| `advisory_cwe` | list | CWE(s) assigned by the advisory (often coarse; not ground truth) |
| `published` | string | advisory publication date |
| `repo_owner`, `repo_name` | string | GitHub repository of the fix |
| `fix_sha` | string | commit SHA of the fix |
| `patch_sha256` | string | hash of the fetched diff; also the duplicate-group key |
| `patch_bytes` | int | size of the fetched diff |
| `n_commits` | int | number of fix commits (max 3) |
| **`cwe_final`** | string | **the label to use** — filter by `analyzable` first |
| **`label_source`** | string | `agreement` / `adjudicated` / `agreement_specific` / `single_model_unverified` |
| **`analyzable`** | bool | **false = the model declined; do not trust `cwe_final`** |
| `cwe_pro`, `cwe_flash` | string | each model's independent CWE |
| `relation` | string | hierarchy relation: `exact`, `more_specific`, `more_general`, `sibling`, `conflict` |
| `advisory_relation` | string | same relation, analysis vs advisory CWE |
| `cwe_adjudicated` | string | CWE chosen by blind adjudication, where it ran |
| `adj_chose` | string | `analysis_1` / `analysis_2` / `neither` (slots anonymised) |
| `adj_rationale` | string | why the adjudicator decided as it did |
| `adj_both_defensible` | bool | both candidate CWEs were reasonable |
| `adj_confidence` | float | adjudicator's calibrated confidence |
| `patch_sufficient_pro` | bool | whether the published fix fully closes the issue |
| `has_detection_heuristic` | bool | a detection heuristic is present |
| `analysis_pro` | JSON string | full Pro analysis (see fields below) |
| `analysis_flash` | JSON string | full Flash cross-check analysis |
| `split` | string | `train` or `eval` |
| `dup_group_size` | int | how many CVEs share this patch hash |
| `analysis_is_model_generated` | bool | always true — the analysis layer is machine-produced |

Fields inside `analysis_pro` / `analysis_flash`: `analyzable`, `cwe_primary`, `cwe_secondary`,
`cwe_confidence`, `vulnerability_class`, `root_cause`, `taint_source`, `taint_sink`, `taint_path`,
`trigger_condition`, `patch_mechanism`, `patch_sufficient`, `patch_reasoning`, `residual_risk`,
`detection_heuristic`, `detection_kind`, `false_positive_risk`, `affected_functions`,
`exploit_preconditions`, `confidence_overall`.

## What you can build with it

- Train or evaluate **vulnerability detection** models on real fixes rather than synthetic bugs
- Benchmark **CWE classification** against cross-checked labels with disagreement preserved
- Study **incomplete patches** — 1,081 rows where the analysis argues the published fix is insufficient
- Mine **detection heuristics** for static-analysis rules, grouped by CWE and language
- Research **LLM agreement and calibration**: two independent analyses plus a blind adjudication
  verdict on every disagreement

## Benchmark split

`split` is `train` (15,107) or `eval` (1,490). 662 patch hashes are shared by more than one CVE — one
commit often fixes several advisories — so the split is **group-aware**: every CVE sharing a patch
hash lands on the same side. Verified: **0 patch hashes span both splits.**

## Licensing and code

Rows carry commit pointers, patch SHA256 and metadata — **not** wholesale source — so each file stays
under its originating repository's licence. Reconstruct full diffs with:

```bash
python3 fetch_full.py patchwork-cve.jsonl.gz --out patches/
```

Dataset CC-BY-4.0 (`LICENSE-DATA`), code MIT (`LICENSE-CODE`). Advisory metadata from OSV and GHSA
(CC-BY-4.0) and NVD (public domain). Analyses generated with Google Gemini via Vertex AI; Google's
Service Specific Terms restrict using model output to create or improve models similar to a Google
model, and that restriction is passed through to users of this dataset.

## Scope and honesty

- **Only public, already-patched CVEs.** No zero-days, no exploit code, no live targets. The output
  is oriented toward detection, not exploitation.
- **Advisory CWEs are not ground truth.** The analysis conflicts with the published advisory ~19% of
  the time; spot-checking found cases where the model's label is the better one. Reported as
  disagreement, not accuracy.
- **Diffs are capped at 32 KB** of security-relevant files (lockfiles, vendored trees and binaries
  dropped first). Large refactor commits are analysed from a subset.
- **CVEs fixed across more than 3 commits are excluded** (~4% of candidates).
- Full method, limitations and audit results: [`DATASHEET.md`](DATASHEET.md) and
  [`RELIABILITY.md`](RELIABILITY.md).

## Citation

```bibtex
@dataset{patchwork_cve_2026,
  title  = {Patchwork: A CWE-Labelled Corpus of Real Patched Vulnerabilities
            with Root-Cause Analysis and Detection Heuristics},
  year   = {2026},
  url    = {https://github.com/TayR-D/patchwork-cve},
  note   = {16,597 CVEs with fix commits, two-model cross-checked CWE labels,
            and blind adjudication of disagreements}
}
```

## Reproducing it

`pipeline/` holds the full pipeline: OSV corpus construction, patch fetching, Vertex batch analysis,
hierarchy-aware agreement scoring, blind adjudication, and export. It was built and run end-to-end on
a fixed GCP credit budget, governed by a spend controller that self-accounts from token usage.

Total compute: **THB 8,870** (~USD 257) across 165M input and 52M output tokens.
