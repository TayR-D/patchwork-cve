# Patchwork

**16,597 real, already-patched CVEs, each with its fix commit and a structured analysis of the
vulnerability — root cause, taint path, why the patch works, and a proposed detection heuristic.**

Public vulnerability datasets (BigVul, CVEfixes, DiverseVul) label a function as vulnerable, assign a
CWE, and stop. What they omit is the reasoning: which input reaches the sink, why the patch closes the
path, and what a detector should key on. That absence is a large part of why detectors overfit to
surface syntax. Patchwork adds that layer.

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

## Reproducing it

`pipeline/` holds the full pipeline: OSV corpus construction, patch fetching, Vertex batch analysis,
hierarchy-aware agreement scoring, blind adjudication, and export. It was built and run end-to-end on
a fixed GCP credit budget, governed by a spend controller that self-accounts from token usage.

Total compute: **THB 8,870** (~USD 257) across 165M input and 52M output tokens.
