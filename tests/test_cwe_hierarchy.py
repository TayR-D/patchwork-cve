import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pipeline"))

import build_cwe_graph
import cwe_rel


class CweRelationshipTests(unittest.TestCase):
    def test_normalizes_numeric_and_case_insensitive_identifiers(self):
        self.assertEqual(cwe_rel.norm("338"), "CWE-338")
        self.assertEqual(cwe_rel.norm(" cwe-338 "), "CWE-338")
        self.assertIsNone(cwe_rel.norm("not-a-cwe"))

    def test_exact_relation(self):
        self.assertEqual(cwe_rel.relation("CWE-79", "79"), "exact")

    def test_transitive_ancestor_relations(self):
        # CWE-917 -> CWE-77 -> CWE-74 in MITRE's Research Concepts view.
        self.assertEqual(cwe_rel.relation("CWE-917", "CWE-74"), "more_specific")
        self.assertEqual(cwe_rel.relation("CWE-74", "CWE-917"), "more_general")

    def test_sibling_relation_uses_a_shared_ancestor(self):
        # CWE-917 descends through CWE-77, while CWE-94 is another CWE-74 child.
        self.assertEqual(cwe_rel.relation("CWE-917", "CWE-94"), "sibling")

    def test_unrelated_branches_conflict(self):
        self.assertEqual(cwe_rel.relation("CWE-22", "CWE-89"), "conflict")

    def test_missing_relation_and_best_relation(self):
        self.assertEqual(cwe_rel.relation(None, "CWE-79"), "missing")
        self.assertEqual(
            cwe_rel.best_relation("CWE-338", ["CWE-79", "CWE-330"]),
            "more_specific",
        )

    def test_resolve_keeps_the_more_specific_label(self):
        self.assertEqual(
            cwe_rel.resolve("CWE-330", "CWE-338"),
            ("CWE-338", "agreement_specific", "more_general"),
        )


class CweGraphBuilderTests(unittest.TestCase):
    XML = b'''<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog Version="4.20" Date="2026-04-30" xmlns="http://cwe.mitre.org/cwe-7">
  <Weaknesses>
    <Weakness ID="20" Name="Child" Abstraction="Base">
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="10" View_ID="1000"/>
        <Related_Weakness Nature="ChildOf" CWE_ID="30" View_ID="1003"/>
        <Related_Weakness Nature="PeerOf" CWE_ID="30" View_ID="1000"/>
      </Related_Weaknesses>
    </Weakness>
    <Weakness ID="10" Name="Parent" Abstraction="Class"/>
    <Weakness ID="30" Name="Other view" Abstraction="Class"/>
  </Weaknesses>
</Weakness_Catalog>'''

    def test_parser_keeps_only_research_view_child_edges(self):
        graph = build_cwe_graph.build_graph(self.XML, archive_sha256="fixture")
        self.assertEqual(graph["parents"]["CWE-20"], ["CWE-10"])
        self.assertEqual(graph["parents"]["CWE-30"], [])
        self.assertEqual(graph["names"]["CWE-10"], "Parent")
        self.assertEqual(graph["abstraction"]["CWE-20"], "Base")
        self.assertEqual(graph["metadata"]["source_archive_sha256"], "fixture")

    def test_checksum_verification_rejects_changed_archives(self):
        digest = hashlib.sha256(b"archive").hexdigest()
        self.assertEqual(build_cwe_graph.verify_archive(b"archive", digest), digest)
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            build_cwe_graph.verify_archive(b"changed", digest)

    def test_extract_xml_reads_only_the_pinned_catalog_name(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as bundle:
            bundle.writestr("cwec_v4.20.xml", self.XML)
        self.assertEqual(build_cwe_graph.extract_xml(stream.getvalue()), self.XML)

    def test_checked_in_graph_matches_a_fresh_render(self):
        checked_in = json.loads((ROOT / "schema" / "cwe_graph.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "graph.json"
            build_cwe_graph.write_graph(checked_in, output)
            self.assertEqual(
                output.read_bytes(),
                (ROOT / "schema" / "cwe_graph.json").read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
