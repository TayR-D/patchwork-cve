# Patchwork — reliability audit

100 rows drawn stratified across every `label_source` and spread over ecosystems, plus automated
checks run over all 16,597 rows. Sample and method are reproducible from `out/audit_sample.json`.

## Manual review

Six adjudicated rows — the hardest cases, where the two models genuinely disagreed — were read
line-by-line against their actual diffs:

| CVE | Final | Verdict |
|---|---|---|
| CVE-2021-4146 | CWE-1284 | Correct. Chosen over Pro's vague CWE-840; the patch validates a quantity. |
| CVE-2025-58769 | CWE-22 | Defensible, arguable. CWE-73 is arguably more precise for PHP stream-wrapper abuse; CWE-22 matches the advisory. |
| CVE-2022-46164 | CWE-1321 | Correct, and notable: Pro assigned CWE-1336 (template engines) to plain prototype pollution. The blind adjudicator overrode it in favour of Flash. |
| CVE-2022-24278 | CWE-159 | Sound. The advisory's CWE-22 looks wrong for a sanitisation-bypass. |
| CVE-2020-15157 | CWE-522 | Correct. More specific than Pro's CWE-200, and matches the advisory. |
| CVE-2026-22175 | CWE-184 | Correct for an allowlist bypass via shell multiplexers. |

5 of 6 clearly correct, 1 defensible. Small sample — treat as a spot check, not a precision estimate.

## Automated checks (all 16,597 rows)

| check | count | rate | disposition |
|---|---:|---:|---|
| refused (`analyzable=false`) | 693 | 4.2% | expected — honest refusals are kept, not dropped |
| **refused but still carrying a CWE** | **692** | **4.2%** | **schema defect, see below** |
| empty detection heuristic | 248 | 1.5% | disclosed limitation |
| no Pass B cross-check | 22 | 0.13% | labelled `single_model_unverified` |
| rows with no final label | 0 | 0% | resolved |

### The refusal defect — read this before using `cwe_final`

`cwe_primary` was a **required** field in the analysis schema. When the model set
`analyzable=false` — declining to analyse a diff it could not interpret — the schema still forced it
to emit a CWE. So 692 rows carry a label the model itself disclaimed.

`analyzable` is surfaced as a top-level column for exactly this reason.
**Filter `WHERE analyzable` before trusting `cwe_final`.** The labels are retained rather than nulled
because they may still carry signal, but they are not cross-check-backed and should not be treated as
ground truth. A future revision should make `cwe_primary` optional when `analyzable=false`.

## Agreement with published advisory CWEs (audited sample)

exact 46%, sibling 16%, more_specific 10%, more_general 2%, conflict 19%, missing 7%.

Divergence from the advisory is **not** an error rate. Advisory CWEs are frequently coarse or
reporter-assigned, and the manual review above found at least one case (CVE-2022-24278) where the
model's label is better than the advisory's. This is reported as disagreement, not accuracy.

## Leakage control

662 patch hashes are shared by more than one CVE (one commit often fixes several advisories). Those
rows are real and are kept, but the train/eval split is **group-aware**: every CVE sharing a patch
hash lands on the same side. Verified: **0 patch hashes span both splits.**
