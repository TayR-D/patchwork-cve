# Patchwork — a CWE-labelled corpus of real, already-patched vulnerabilities

## Motivation

Public vulnerability-detection datasets (BigVul, CVEfixes, DiverseVul) label a function as
vulnerable and assign a CWE, and stop there. What they omit is the reasoning: which input
reaches the sink, why the patch closes the path, and what a detector should key on. That
absence is a large part of why detectors overfit to surface syntax. Patchwork adds that
layer to a corpus of already-public, already-patched CVEs.

## Composition

- **16,611 CVEs**, each with a GitHub fix commit and its diff
- Pass A (Gemini 2.5 Pro) analyses: 16,607 rows, 10 unparseable
- Pass B (Gemini 2.5 Flash) cross-check: 16,610 rows, 22 unparseable

### By ecosystem

| ecosystem | CVEs |
|---|---:|
| PyPI | 3,433 |
| npm | 3,054 |
| Maven | 2,924 |
| Packagist | 2,841 |
| Go | 2,291 |
| RubyGems | 525 |
| GIT | 475 |
| crates.io | 430 |
| NuGet | 427 |
| Hex | 167 |
| GitHub Actions | 26 |
| Hackage | 10 |
| Pub | 8 |

### By year

| year | CVEs |
|---|---:|
| 2015 | 188 |
| 2016 | 269 |
| 2017 | 388 |
| 2018 | 601 |
| 2019 | 594 |
| 2020 | 1,010 |
| 2021 | 1,333 |
| 2022 | 1,776 |
| 2023 | 1,698 |
| 2024 | 1,679 |
| 2025 | 2,023 |
| 2026 | 4,368 |

## Labelling process

Two models analyse each diff **independently**. Confidence is their agreement scored against
the MITRE CWE hierarchy — not any model's self-reported confidence, which measured a useless
0.94 mean on a pilot where it returned 1.0 while giving three different answers across three
runs. Ancestor/descendant CWE pairs count as compatible (the more specific label wins);
siblings and unrelated pairs go to a third adjudication pass that sees both analyses
**anonymised and order-randomised**, so it cannot defer to the stronger model by reputation.

| relation | rows | share |
|---|---:|---:|
| exact | 11,485 | 69.2% |
| conflict | 1,836 | 11.1% |
| sibling | 1,586 | 9.6% |
| more_specific | 1,027 | 6.2% |
| more_general | 613 | 3.7% |
| missing | 60 | 0.4% |

**Disagreement is preserved on every row.** A row where the models diverged is marked as
such rather than silently resolved; the adjudicated label is recorded alongside both originals.

### Does the cross-check earn its cost?

3,450 disagreements were adjudicated blind. Decoding which model each anonymous slot held:

| outcome | rows | share |
|---|---:|---:|
| Pro's label preferred | 2,196 | 63.7% |
| Flash's label preferred | 834 | 24.2% |
| neither -- adjudicator supplied a third CWE | 416 | 12.1% |

A single-model (Pro-only) corpus would therefore carry the wrong primary CWE on roughly
**36% of these rows** -- 834 where Flash was right and 416 where both were wrong. That is the
concrete value of the second pass, measured rather than assumed.

Position bias check: analysis_1 chosen 44.8% vs analysis_2 43.2%. Slot order was randomised per CVE and model identity hidden, so
this near-even split indicates the adjudicator judged on evidence rather than position.

`both_defensible` was set on 77.9% of adjudications, consistent with
the hierarchy finding: most apparent disagreement is a difference of abstraction level.

## Known limitations

- **Advisory CWEs are not ground truth.** The published advisory CWE is often coarse or
  reporter-assigned; the pilot found the primary analysis conflicting with it ~7% of the time
  and absent entirely for ~27% of rows. Treat disagreement with the advisory as signal, not error.
- **Ecosystem skew.** Coverage follows OSV's, which over-represents package ecosystems with
  strong advisory practice. The distribution above is reported rather than corrected.
- **Truncation.** Diffs are capped at 32KB of security-relevant files (lockfiles, vendored
  trees and binaries dropped first). Large refactor commits are analysed from a subset.
- **Multi-commit fixes.** CVEs fixed across more than 3 commits are excluded (~4% of candidates).
- **Model-generated content.** Every analysis field is machine-produced and marked
  `analysis_is_model_generated`. The factual backbone — CVE identity, repository, fix commit,
  diff, patch hash — comes from public sources, not from a model.

## Distribution and licensing

Rows carry commit pointers, patch SHA256 and minimal excerpts rather than wholesale source,
so each file stays under its originating repository's licence; a reconstruction script ships
with the release. Advisory metadata derives from OSV and GHSA (CC-BY-4.0) and NVD (public
domain). Dataset CC-BY-4.0; code MIT.

Analyses were generated with Google Gemini via Vertex AI. Google's Service Specific Terms
restrict using model output to create or improve models similar to a Google model; this
corpus is published for vulnerability-detection research and evaluation, and that restriction
is passed through here so downstream users can honour it.

## Provenance of this document

Generated from live pipeline state: 16,611 candidates in BigQuery, 
37 ledger entries totalling THB 8,869.69 of compute.
No figure in this datasheet was typed by hand.
