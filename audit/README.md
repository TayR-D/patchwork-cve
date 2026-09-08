# v1.0 audit sample

`v1.0_audit_sample.json` is the **exact** 100-row sample behind the figures in
[`../RELIABILITY.md`](../RELIABILITY.md). It was drawn from `dataset_final` before release, stratified
across every `label_source` and spread over ecosystems, with `random.seed(42)`.

- rows: 100
- sha256: `1edad0cbee870d614fbef25a37b654eae1c1d2d73f99ac8a4137c6a31658dbfe`
- strata: {"agreement": 40, "adjudicated": 40, "agreement_specific": 15, "needs_adjudication": 5}

Publishing it closes the gap noted in #1: the sample-level figures were previously unverifiable
because the sample itself was never released. It still is not a *reproducible draw* — the selection
depended on BigQuery row ordering at export time, which is not pinned. Treat it as the auditable
record of what was actually checked, not as a recipe that regenerates itself.

`pipeline/make_audit_sample.py` (added in #1) is the deterministic method for future audits.
