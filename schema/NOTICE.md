# CWE graph provenance

`cwe_graph.json` is derived from the MITRE Common Weakness Enumeration (CWE)
4.20 XML catalog, published 2026-04-30. It contains weakness names,
abstraction levels, and `ChildOf` relationships from the Research Concepts
view (CWE-1000). The source URL and archive SHA-256 are embedded in the JSON;
`pipeline/build_cwe_graph.py` verifies that checksum before regenerating it.
This pinned graph was added after v1.0 to replace its missing pipeline input;
it does not prove which graph or catalog version produced v1.0's published
agreement counts.

Copyright © 2006–2026, The MITRE Corporation. Use of CWE is subject to the
[MITRE CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html). CWE is a
trademark of The MITRE Corporation.
