#!/usr/bin/env python3
"""Build the hierarchy data consumed by :mod:`cwe_rel`.

The input is the pinned MITRE CWE 4.20 XML archive.  Pinning both the release
URL and its SHA-256 keeps agreement scoring reproducible even after MITRE
publishes a newer catalog.  Only ``ChildOf`` relationships from the Research
Concepts view (CWE-1000) are included; mixing the alternative views would merge
several different taxonomies into one graph.
"""

import argparse
import hashlib
import json
from pathlib import Path
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from io import BytesIO


CWE_VERSION = "4.20"
CWE_VIEW_ID = "1000"
CWE_VIEW_NAME = "Research Concepts"
CWE_URL = f"https://cwe.mitre.org/data/xml/cwec_v{CWE_VERSION}.xml.zip"
CWE_ARCHIVE_SHA256 = "3976f599e5e5200219a3108bb896d06e2a88fbb293369e1883cb423a5e9d7d50"
CWE_COPYRIGHT = "Copyright © 2006–2026, The MITRE Corporation"
CWE_TERMS_URL = "https://cwe.mitre.org/about/termsofuse.html"
USER_AGENT = "patchwork-cve-cwe-graph/1.0"

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "schema" / "cwe_graph.json"


def download_archive(url=CWE_URL):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def verify_archive(archive, expected_sha256=CWE_ARCHIVE_SHA256):
    actual = hashlib.sha256(archive).hexdigest()
    if actual != expected_sha256:
        raise ValueError(
            "MITRE CWE archive checksum mismatch: "
            f"expected {expected_sha256}, got {actual}"
        )
    return actual


def extract_xml(archive):
    expected_name = f"cwec_v{CWE_VERSION}.xml"
    with zipfile.ZipFile(BytesIO(archive)) as bundle:
        if expected_name not in bundle.namelist():
            raise ValueError(f"CWE archive does not contain {expected_name}")
        return bundle.read(expected_name)


def _numeric_cwe_key(cwe):
    return int(cwe.removeprefix("CWE-"))


def build_graph(xml_bytes, archive_sha256=CWE_ARCHIVE_SHA256, view_id=CWE_VIEW_ID):
    root = ET.fromstring(xml_bytes)
    namespace = root.tag[1:].split("}", 1)[0] if root.tag.startswith("{") else ""
    prefix = f"{{{namespace}}}" if namespace else ""
    version = root.get("Version")
    if version != CWE_VERSION:
        raise ValueError(f"expected CWE {CWE_VERSION}, found {version or 'unknown'}")

    weaknesses = root.findall(f"{prefix}Weaknesses/{prefix}Weakness")
    names = {}
    abstraction = {}
    parents = {}
    for weakness in weaknesses:
        cwe = f"CWE-{weakness.get('ID')}"
        names[cwe] = weakness.get("Name") or ""
        abstraction[cwe] = weakness.get("Abstraction") or ""
        related = weakness.find(f"{prefix}Related_Weaknesses")
        parent_ids = set()
        if related is not None:
            for relation in related.findall(f"{prefix}Related_Weakness"):
                if relation.get("Nature") == "ChildOf" and relation.get("View_ID") == view_id:
                    parent_ids.add(f"CWE-{relation.get('CWE_ID')}")
        parents[cwe] = sorted(parent_ids, key=_numeric_cwe_key)

    known = set(names)
    dangling = sorted(
        {parent for values in parents.values() for parent in values if parent not in known},
        key=_numeric_cwe_key,
    )
    if dangling:
        raise ValueError(f"CWE graph has unknown parents: {', '.join(dangling[:10])}")

    order = sorted(known, key=_numeric_cwe_key)
    return {
        "metadata": {
            "source": CWE_URL,
            "source_version": version,
            "source_published": root.get("Date"),
            "source_archive_sha256": archive_sha256,
            "view_id": view_id,
            "view_name": CWE_VIEW_NAME,
            "generated_by": "pipeline/build_cwe_graph.py",
            "copyright": CWE_COPYRIGHT,
            "terms": CWE_TERMS_URL,
        },
        "parents": {cwe: parents[cwe] for cwe in order},
        "names": {cwe: names[cwe] for cwe in order},
        "abstraction": {cwe: abstraction[cwe] for cwe in order},
    }


def write_graph(graph, output):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(graph, ensure_ascii=False, indent=2) + "\n"
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8")
    temporary.replace(output)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        help="local copy of the pinned MITRE XML ZIP (otherwise it is downloaded)",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)

    archive = args.source.read_bytes() if args.source else download_archive()
    digest = verify_archive(archive)
    graph = build_graph(extract_xml(archive), archive_sha256=digest)
    write_graph(graph, args.output)
    edges = sum(len(values) for values in graph["parents"].values())
    print(
        f"wrote {args.output} with {len(graph['names'])} CWEs and {edges} "
        f"ChildOf edges from CWE {CWE_VERSION} view {CWE_VIEW_ID}"
    )


if __name__ == "__main__":
    main()
