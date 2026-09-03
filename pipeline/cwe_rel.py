#!/usr/bin/env python3
"""Hierarchy-aware CWE comparison.

String equality badly understates model agreement: CWE-917 vs CWE-94 or CWE-285
vs CWE-284 are ancestor/descendant pairs, not contradictions. Measured on the
day-1 pilot, string equality read 67% agreement where hierarchy-aware read 79%
compatible with only 12.5% true conflict.
"""
import json, os, functools

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_G = json.load(open(os.path.join(R, "schema", "cwe_graph.json")))
PARENTS, NAMES, ABSTRACTION = _G["parents"], _G["names"], _G.get("abstraction", {})

ORDER = ["exact", "more_specific", "more_general", "sibling", "conflict", "missing"]
COMPATIBLE = {"exact", "more_specific", "more_general"}

@functools.lru_cache(maxsize=None)
def ancestors(cwe):
    seen, stack = set(), list(PARENTS.get(cwe, []))
    while stack:
        x = stack.pop()
        if x in seen: continue
        seen.add(x); stack.extend(PARENTS.get(x, []))
    return frozenset(seen)

def norm(c):
    if not c: return None
    c = str(c).strip().upper().replace(" ", "")
    if c.isdigit(): c = "CWE-" + c
    if not c.startswith("CWE-"): return None
    return c

def relation(a, b):
    """Relation of `a` (primary) to `b` (reference)."""
    a, b = norm(a), norm(b)
    if not a or not b: return "missing"
    if a == b: return "exact"
    if b in ancestors(a): return "more_specific"
    if a in ancestors(b): return "more_general"
    if ancestors(a) & ancestors(b): return "sibling"
    return "conflict"

def best_relation(a, refs):
    """Best (most favourable) relation of `a` against a list of reference CWEs."""
    if not refs: return "missing"
    return min((relation(a, r) for r in refs), key=lambda r: ORDER.index(r))

def is_compatible(rel): return rel in COMPATIBLE

def resolve(pro_cwe, flash_cwe):
    """Final label + provenance, preserving the disagreement either way."""
    rel = relation(pro_cwe, flash_cwe)
    if rel == "exact":          return norm(pro_cwe), "agreement", rel
    if rel == "more_specific":  return norm(pro_cwe), "agreement_specific", rel
    if rel == "more_general":   return norm(flash_cwe), "agreement_specific", rel
    return None, "needs_adjudication", rel   # sibling + conflict -> Pass C candidates

if __name__ == "__main__":
    for a, b in [("CWE-917","CWE-94"),("CWE-285","CWE-284"),("CWE-79","CWE-79"),
                 ("CWE-59","CWE-362"),("CWE-338","CWE-330")]:
        print(f"{a:<9} vs {b:<9} -> {relation(a,b):<14} resolve={resolve(a,b)}")
