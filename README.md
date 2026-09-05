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

# v1.0-compatible refusal filter
usable = df[df.analyzable & df.cwe_final.notna()]

# Datasets rebuilt with the current pipeline expose stricter per-pass gates.
if "crosscheck_usable" in df.columns:
    usable = df[(df.usable_pro | df.usable_flash) & df.cwe_final.notna()]
    crosschecked = df[df.crosscheck_usable]
```

## Read this before using `cwe_final`

The current pipeline allows `cwe_primary` to be null or absent when a model sets
`analyzable=false`. It also treats a response as usable only when it parsed, completed normally,
explicitly opted into analysis, and supplied a CWE identifier present in the pinned catalog.

`analyzable_pro` and `analyzable_flash` preserve each model's explicit decision. `usable_pro` and
`usable_flash` apply the stricter validation above, and `crosscheck_usable` is true only when both
passes are usable. A single usable pass may supply `cwe_final`, but its source is explicitly
`single_model_unverified`; if neither pass is usable, `cwe_final`, `label_source`, and `relation` are
null. Refused outputs retain their raw `cwe_pro` / `cwe_flash` values for audit but never receive an
agreement label or enter adjudication.

For backward compatibility, top-level `analyzable` remains an alias for Pro's explicit analyzability
decision (missing or malformed decisions become false). Prefer `crosscheck_usable` when consuming
cross-checked labels.

The v1.0 artifact predates this pipeline fix: its schema forced a CWE on refusals, including 692 rows
(4.2%) carrying a label the model itself disclaimed. Filter those files on `analyzable` before using
`cwe_final`.

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

**Model output is preserved on every row.** `cwe_pro` and `cwe_flash` retain the raw labels when
present. `relation` is populated only when both analyses are usable, so refused or missing passes
cannot masquerade as cross-checked evidence.

### Did the second model earn its cost?

3,450 disagreements were adjudicated blind. Decoding which model held each anonymous slot:

| outcome | share |
|---|---:|
| Pro's label preferred | 63.7% |
| Flash's label preferred | 24.2% |
| neither — adjudicator supplied a third CWE | 12.1% |

Using Pro alone would produce a different primary CWE from the adjudicator on roughly **36% of
disagreement rows**. That is model disagreement, not a measured error rate. Slot 1 was chosen 44.8%
of the time versus 43.2% for slot 2; this is a useful diagnostic, but does not by itself prove the
absence of position bias or establish label correctness.

## Schema

The refusal gates and versioned patch-provenance columns below describe datasets rebuilt with the
current pipeline. They are not present in the published v1.0 files unless noted as backward-compatible.

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
| `candidate_fingerprint` | string | hash of the full advisory/commit candidate plus collected patch hash |
| `patch_sha256` | string | hash of the fetched diff; also the duplicate-group key |
| `patch_bytes` | int | size of the fetched diff |
| `n_commits` | int | number of fix commits (max 3) |
| `patch_format` | string | versioned recipe used to assemble the collected patch bytes |
| `patch_representation`, `patch_joiner` | string | source representation and deterministic part separator |
| `patch_max_bytes_per_commit` | int | collection cap applied independently to each source commit |
| `patch_commits` | list | ordered commit descriptors with per-part hashes and byte caps |
| `patch_truncated` | bool | whether any source response exceeded its collection byte cap |
| `patch_partial_fetch` | bool | whether any listed source commit failed to fetch (always false in a release) |
| `patch_complete` | bool | false when collection intentionally truncated a source response |
| **`cwe_final`** | string/null | **the label to use** — in current builds require `usable_pro OR usable_flash`; for v1.0 require `analyzable` |
| **`label_source`** | string/null | `agreement` / `adjudicated` / `agreement_specific` / `single_model_unverified` / `adjudication_missing`; null when unusable |
| **`analyzable`** | bool | backward-compatible alias for Pro's explicit analyzability decision |
| `analyzable_pro`, `analyzable_flash` | bool/null | each model's explicit analyzability decision |
| `usable_pro`, `usable_flash` | bool | pass parsed and completed with `analyzable=true` and a known CWE |
| **`crosscheck_usable`** | bool | **true only when both independent analyses are usable** |
| `analysis_patch_sha256` | string | patch hash to which the selected model records are bound |
| `analysis_candidate_fingerprint` | string | candidate fingerprint to which those records are bound |
| `pass_pro_record_sha256`, `pass_flash_record_sha256` | string/null | fingerprints of the exact selected pass records |
| `analysis_pair_sha256` | string/null | fingerprint binding adjudication to the selected Pro/Flash pair |
| `analysis_status` | string | `crosschecked` / `pro_only` / `flash_only` / `no_usable_analysis` |
| `pass_pro_present`, `pass_flash_present` | bool | whether each model returned a stored pass record |
| `cwe_pro`, `cwe_flash` | string | each model's independent CWE |
| `relation` | string/null | hierarchy relation for usable cross-checks; null if either pass is unusable |
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

The types above are Parquet/logical types. BigQuery exports `INT64` values as JSON strings, so
JSONL readers should cast `n_commits`, `patch_bytes`, `patch_max_bytes_per_commit`,
`dup_group_size`, and integer fields nested under `patch_commits`.

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
under its originating repository's licence. Reconstruct and verify the exact bytes used for analysis
with:

```bash
python3 fetch_full.py patchwork-cve.jsonl.gz --out patches/
```

Datasets rebuilt with the current pipeline include ordered `patch_commits`, representation, joiner,
and truncation metadata, allowing exact reconstruction of multi-commit and capped records.
The v1.0 release omitted that provenance: its single, uncapped commit records remain reconstructable,
but multi-commit and collection-truncated rows will report `hash_mismatch`. Mismatched bytes are not
written unless `--write-mismatches` is explicitly supplied.

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

`pipeline/` contains the stage implementations for OSV corpus construction, patch fetching, Vertex
batch analysis, hierarchy-aware agreement scoring, blind adjudication, and export. Python 3.9 or
newer is required. The dependency-free local stages start with:

```bash
python3 pipeline/build_cwe_graph.py  # verifies pinned MITRE CWE 4.20 input
python3 pipeline/build_corpus.py     # writes out/candidates.jsonl from the current OSV bulk feed
python3 pipeline/fetch_patches.py    # writes patches and byte-level provenance under out/
python3 pipeline/make_shards.py      # writes the Pass A plan under state/
python3 -m unittest discover -s tests -v
```

The generated CWE graph is checked in, so agreement scoring and tests run offline. Its source URL,
version, view, and archive SHA-256 are recorded in `schema/cwe_graph.json`; see
[`schema/NOTICE.md`](schema/NOTICE.md).
It is an auditable replacement for the graph omitted from v1.0, not evidence that the published
v1.0 agreement counts used these exact edges.

The paid stages additionally require authenticated `gcloud` and `bq` CLIs, a Vertex AI project,
GCS bucket, and BigQuery `patchwork` dataset. Configure the project-specific defaults with
`PW_PROJECT`, `PW_REGION`, and `PW_BUCKET` before using `pipeline/session.py` and the later drivers.
Pass tables produced before patch-hash binding was added are intentionally incompatible; start with
empty `pass_a`, `pass_b`, and `pass_c` tables and regenerate shard state rather than reusing unbound
v1.0 cloud rows. New jobs use unique attempt paths and verify provenance embedded in each echoed
request, so retry output cannot be confused with another shard attempt.

This repository is not yet a bit-for-bit recipe for the v1.0 release. The OSV input is a live feed,
and the exact source snapshot, Pass B shard plan/cloud state, model outputs, and original audit sample
were not published. In particular, `make_shards.py` creates only the Pass A plan; do not claim a fresh
end-to-end reproduction until the Pass B orchestration and immutable inputs are versioned. The audit
helper in `pipeline/make_audit_sample.py` creates a new deterministic future sample, not the missing
v1.0 sample.

Total compute: **THB 8,870** (~USD 257) across 165M input and 52M output tokens.
