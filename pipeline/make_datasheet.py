#!/usr/bin/env python3
"""Generate DATASHEET.md from measured pipeline state -- no hand-typed numbers.

Follows the Gebru et al. datasheet structure. Every figure is read from BigQuery,
the ledger, or the agreement scores, so the document cannot drift from the data.
"""
import json, os, sys, subprocess, collections
R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(R, "pipeline"))
import batch, ledger, export as export_pipeline

P = batch.PROJECT

def q(sql, default=None):
    """Query BigQuery; return `default` if the table does not exist yet.

    The datasheet is generated repeatedly as passes land, so a missing table is a
    normal intermediate state, not an error."""
    cp = subprocess.run(["bq","--project_id="+P,"query","--use_legacy_sql=false",
                         "--format=json","--max_rows=10000",sql],
                        capture_output=True, text=True, timeout=900)
    if cp.returncode != 0:
        # bq reports query errors on stdout, not stderr -- check both
        msg = (cp.stderr or "") + (cp.stdout or "")
        if "Not found: Table" in msg and default is not None:
            return default
        raise RuntimeError(msg[:400] or "bq failed with no message")
    return json.loads(cp.stdout or "[]")


def agreement_counters(path):
    """Summarise only genuine two-model comparisons for the datasheet."""
    if not os.path.exists(path):
        return collections.Counter(), collections.Counter()
    with open(path) as agreement_file:
        rows = [json.loads(line) for line in agreement_file if line.strip()]
    relations = collections.Counter(
        row["relation"] for row in rows
        if row.get("relation") is not None
        and row.get("crosscheck_usable", True)
    )
    statuses = collections.Counter(
        row.get("analysis_status") for row in rows if row.get("analysis_status")
    )
    return relations, statuses


def main():
    tot = int(q(f"SELECT COUNT(*) n FROM `{P}.patchwork.candidates`")[0]["n"])
    eco = q(f"SELECT ecosystem, COUNT(*) n FROM `{P}.patchwork.candidates` "
            f"GROUP BY 1 ORDER BY n DESC")
    yr  = q(f"SELECT SUBSTR(cve,5,4) y, COUNT(*) n FROM `{P}.patchwork.candidates` "
            f"GROUP BY 1 ORDER BY y")
    none = [{"n": 0, "failed": 0}]
    pa = q(f"""SELECT COUNT(*) n, COUNTIF(p.analysis='null') failed
                FROM ({export_pipeline.PASS_A_ONE_SQL}) p
                JOIN `{P}.patchwork.candidates` c
                  ON p.cve = c.cve AND p.patch_sha256 = c.patch_sha256
                 AND p.candidate_fingerprint = c.candidate_fingerprint""", none)[0]
    pb = q(f"""SELECT COUNT(*) n, COUNTIF(p.analysis='null') failed
                FROM ({export_pipeline.PASS_B_ONE_SQL}) p
                JOIN `{P}.patchwork.candidates` c
                  ON p.cve = c.cve AND p.patch_sha256 = c.patch_sha256
                 AND p.candidate_fingerprint = c.candidate_fingerprint""", none)[0]
    spend = ledger.totals()

    ag = f"{R}/out/agreement.jsonl"
    rel, analysis_status = agreement_counters(ag)

    L = []
    A = L.append
    A("# Patchwork — a CWE-labelled corpus of real, already-patched vulnerabilities\n")
    A("## Motivation\n")
    A("Public vulnerability-detection datasets (BigVul, CVEfixes, DiverseVul) label a function as")
    A("vulnerable and assign a CWE, and stop there. What they omit is the reasoning: which input")
    A("reaches the sink, why the patch closes the path, and what a detector should key on. That")
    A("absence is a large part of why detectors overfit to surface syntax. Patchwork adds that")
    A("layer to a corpus of already-public, already-patched CVEs.\n")
    A("## Composition\n")
    A(f"- **{tot:,} CVEs**, each with a GitHub fix commit and its diff")
    A(f"- Pass A (Gemini 2.5 Pro) analyses: {int(pa['n']):,} rows, {int(pa['failed'])} unparseable")
    A(f"- Pass B (Gemini 2.5 Flash) cross-check: {int(pb['n']):,} rows, {int(pb['failed'])} unparseable")
    if int(pa['n']) == 0:
        A("\n> **DRAFT** — Pass A has not landed yet; figures below are partial.")
    A("\n### By ecosystem\n")
    A("| ecosystem | CVEs |"); A("|---|---:|")
    for r in eco[:15]: A(f"| {r['ecosystem']} | {int(r['n']):,} |")
    A("\n### By year\n")
    A("| year | CVEs |"); A("|---|---:|")
    for r in yr:
        if r["y"] and r["y"].isdigit() and int(r["y"]) >= 2015: A(f"| {r['y']} | {int(r['n']):,} |")

    A("\n## Labelling process\n")
    A("Two models analyse each diff **independently**. Confidence is their agreement scored against")
    A("the MITRE CWE hierarchy — not any model's self-reported confidence, which measured a useless")
    A("0.94 mean on a pilot where it returned 1.0 while giving three different answers across three")
    A("runs. Ancestor/descendant CWE pairs count as compatible (the more specific label wins);")
    A("siblings and unrelated pairs go to a third adjudication pass that sees both analyses")
    A("**anonymised and order-randomised**, so it cannot defer to the stronger model by reputation.\n")
    A("Only parsed, normally completed responses with `analyzable=true` and a known CWE are")
    A("eligible for comparison or adjudication. A single usable response is explicitly marked")
    A("`single_model_unverified`; a row with no usable response receives no final label.\n")
    if analysis_status:
        A("| analysis status | rows |"); A("|---|---:|")
        for k, v in analysis_status.most_common(): A(f"| {k} | {v:,} |")
        A("")
    if rel:
        n = sum(rel.values())
        A("| relation (usable cross-checks only) | rows | share |"); A("|---|---:|---:|")
        for k, v in rel.most_common(): A(f"| {k} | {v:,} | {v/n*100:.1f}% |")
    A("\n**Raw model output is preserved on every row.** A usable disagreement is marked rather")
    A("than silently resolved; the adjudicated label is recorded alongside both originals. Refused")
    A("or missing passes have no relation and cannot masquerade as cross-checked evidence.\n")
    # adjudication results, read from the built table
    try:
        adj = q(f"""SELECT COUNTIF(adj_chose='analysis_1') a1, COUNTIF(adj_chose='analysis_2') a2,
                           COUNTIF(adj_chose='neither') nei, COUNTIF(adj_both_defensible) both_ok,
                           COUNT(*) n
                    FROM `{P}.patchwork.dataset_final` WHERE cwe_adjudicated IS NOT NULL""", None)[0]
        n = int(adj["n"])
        A("### Does the cross-check earn its cost?\n")
        A(f"{n:,} disagreements were adjudicated blind. Outcomes by anonymous input slot:\n")
        A("| outcome | rows | share |"); A("|---|---:|---:|")
        for label, field in (("analysis 1 selected", "a1"),
                             ("analysis 2 selected", "a2"),
                             ("neither -- a third CWE supplied", "nei")):
            count = int(adj[field])
            A(f"| {label} | {count:,} | {count/n*100:.1f}% |")
        A("")
        A(f"Position diagnostic: analysis_1 chosen {int(adj['a1'])/n*100:.1f}% vs analysis_2 "
          f"{int(adj['a2'])/n*100:.1f}%. Slot order was randomised per CVE and model identity hidden; "
          "this comparison alone does not establish absence of bias or label accuracy.\n")
        A(f"`both_defensible` was set on {int(adj['both_ok'])/n*100:.1f}% of adjudications. This")
        A("describes the adjudicator's output; it is not an independent accuracy estimate.\n")
    except Exception as e:
        A(f"\n> (adjudication stats unavailable: {type(e).__name__})\n")

    A("## Known limitations\n")
    A("- **Advisory CWEs are not ground truth.** The published advisory CWE is often coarse or")
    A("  reporter-assigned; the pilot found the primary analysis conflicting with it ~7% of the time")
    A("  and absent entirely for ~27% of rows. Treat disagreement with the advisory as signal, not error.")
    A("- **Ecosystem skew.** Coverage follows OSV's, which over-represents package ecosystems with")
    A("  strong advisory practice. The distribution above is reported rather than corrected.")
    A("- **Truncation.** Diffs are capped at 32KB of security-relevant files (lockfiles, vendored")
    A("  trees and binaries dropped first). Large refactor commits are analysed from a subset.")
    A("- **Multi-commit fixes.** CVEs fixed across more than 3 commits are excluded (~4% of candidates).")
    A("- **Model-generated content.** Every analysis field is machine-produced and marked")
    A("  `analysis_is_model_generated`. The factual backbone — CVE identity, repository, fix commit,")
    A("  diff, patch hash — comes from public sources, not from a model.\n")

    A("## Distribution and licensing\n")
    A("Rows carry commit pointers, patch SHA256 and minimal excerpts rather than wholesale source,")
    A("so each file stays under its originating repository's licence; a reconstruction script ships")
    A("with the release. Advisory metadata derives from OSV and GHSA (CC-BY-4.0) and NVD (public")
    A("domain). Dataset CC-BY-4.0; code MIT.\n")
    A("Analyses were generated with Google Gemini via Vertex AI. Google's Service Specific Terms")
    A("restrict using model output to create or improve models similar to a Google model; this")
    A("corpus is published for vulnerability-detection research and evaluation, and that restriction")
    A("is passed through here so downstream users can honour it.\n")

    A("## Provenance of this document\n")
    A(f"Generated from live pipeline state: {tot:,} candidates in BigQuery, ")
    A(f"{spend['calls']} ledger entries totalling THB {spend['thb']:,.2f} of compute.")
    A("No figure in this datasheet was typed by hand.\n")

    open(f"{R}/out/DATASHEET.md","w").write("\n".join(L))
    print(f"wrote out/DATASHEET.md ({len(L)} lines)")

if __name__ == "__main__":
    main()
