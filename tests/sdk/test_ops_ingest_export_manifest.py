"""Unit tests for ``indiek.ops.ingest``, ``indiek.ops.export`` and ``indiek.ops.manifest``."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from _builders import Builder

from indiek.core.archive import ArchiveStore
from indiek.core.author import Author
from indiek.core.errors import ArchiveRuleError, UnknownItemError
from indiek.core.index import ArchiveIndex
from indiek.core.models import FORMAT_VERSION
from indiek.ops import tags
from indiek.ops.export import export_graphml
from indiek.ops.ingest import IngestResult, ingest, list_folder
from indiek.ops.manifest import write_manifest

AUTHOR = Author.from_seed_hex("aa" * 32)  # public test vector, not a secret
NS = {"g": "http://graphml.graphdrawing.org/xmlns"}


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "archive"


def _index(root: Path) -> ArchiveIndex:
    return ArchiveIndex(ArchiveStore.open(root))


# --- ingest ------------------------------------------------------------------------


@pytest.fixture
def folder(tmp_path: Path) -> Path:
    folder = tmp_path / "in"
    folder.mkdir()
    (folder / "b.txt").write_text("beta", encoding="utf-8")
    (folder / "a.txt").write_text("alpha", encoding="utf-8")
    return folder


def test_list_folder_is_sorted_and_not_recursive(folder: Path) -> None:
    (folder / "sub").mkdir()
    (folder / "sub" / "deep.txt").write_text("x", encoding="utf-8")
    assert list_folder(folder) == [folder / "a.txt", folder / "b.txt", folder / "sub"]


def test_ingest_nodes_then_edges(root: Path, folder: Path) -> None:
    result = ingest(
        _index(root),
        AUTHOR,
        file_paths=list_folder(folder),
        edge_definitions=["e1,e2,links, with commas\n"],
    )
    assert isinstance(result, IngestResult)
    assert (len(result.node_ids), len(result.edge_ids)) == (2, 1)
    index = _index(root)
    assert [index.get(f"e{i}").body["title"] for i in (1, 2)] == ["a", "b"]
    edge = index.get("e3")
    assert edge.id == result.edge_ids[0]
    assert (edge.body["source_node"], edge.body["target_node"]) == tuple(
        map(str, result.node_ids)
    )
    # known quirk (INGEST-ROBUSTNESS): the trailing newline is kept
    assert index.store.blobs.get_text(edge.body["blob_hash"]) == "links, with commas\n"


def test_ingest_stores_a_subfolder_path_as_text(root: Path, folder: Path) -> None:
    (folder / "sub").mkdir()
    ingest(_index(root), AUTHOR, file_paths=list_folder(folder))
    body = _index(root).get("e3").body
    assert body["title"] == "sub"
    assert _index(root).store.blobs.get_text(body["blob_hash"]) == str(folder / "sub")


def test_ingest_aborts_on_unsupported_file_keeping_earlier_nodes(
    root: Path, folder: Path
) -> None:
    (folder / "c.csv").write_text("x,y", encoding="utf-8")
    with pytest.raises(ArchiveRuleError, match="Unsupported archival media type"):
        ingest(_index(root), AUTHOR, file_paths=list_folder(folder))
    assert _index(root).store.base_count == 2


def test_ingest_nothing(root: Path) -> None:
    assert ingest(_index(root), AUTHOR) == IngestResult(node_ids=[], edge_ids=[])


# --- export ------------------------------------------------------------------------


@pytest.fixture
def tagged(root: Path) -> None:
    build = Builder(root, AUTHOR)
    a, b, c = build.node("a"), build.node("b"), build.node("c")
    build.edge(a, b, "ab")
    build.supersede_node(a, "a2")
    t1 = tags.create_tag(_index(root), AUTHOR, "t1", "d", "node")  # m1
    tags.create_tag(_index(root), AUTHOR, "t2", "d", "node")  # m2
    tags.set_tag(_index(root), AUTHOR, t1, "e1")
    tags.set_tag(_index(root), AUTHOR, "m2", "e2")
    del c


def _parse(path: Path) -> ET.Element:
    return ET.parse(path).getroot()


def test_export_everything(root: Path, tmp_path: Path, tagged: None) -> None:
    out = export_graphml(_index(root), tmp_path / "g.graphml")
    graph = _parse(out).find("g:graph", NS)
    assert graph is not None and graph.get("edgedefault") == "directed"
    assert len(graph.findall("g:node", NS)) == 3
    assert len(graph.findall("g:edge", NS)) == 1
    labels = [
        d.text for d in graph.iter(f"{{{NS['g']}}}data") if d.get("key") == "node_label"
    ]
    # known quirk (EXPORT-SUPERSEDES): supersede events are ignored
    assert labels == ["a", "b", "c"]


def test_export_tag_filter_is_or(root: Path, tmp_path: Path, tagged: None) -> None:
    out = export_graphml(_index(root), tmp_path / "g.graphml", tags=["m1", "m2"])
    graph = _parse(out).find("g:graph", NS)
    assert graph is not None
    assert len(graph.findall("g:node", NS)) == 2
    assert graph.findall("g:edge", NS) == []


def test_export_unknown_tag(root: Path, tmp_path: Path, tagged: None) -> None:
    with pytest.raises(UnknownItemError):
        export_graphml(_index(root), tmp_path / "g.graphml", tags=["m99"])


# --- manifest ----------------------------------------------------------------------


def test_write_manifest(root: Path) -> None:
    root.mkdir()
    path = write_manifest(root, [AUTHOR.public_key_hex])
    assert path == root.resolve() / "MANIFEST.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["format_version"] == FORMAT_VERSION == "3.1"
    assert data["authors"] == [
        {"public_key": AUTHOR.public_key_hex, "algorithm": "Ed25519"}
    ]
    assert {"blob_store", "event_log", "seal_log", "schemas"} <= data.keys()
    assert {"SealModel", "LogTip", "MetaEventHeader"} <= data["schemas"].keys()
    assert (root / "SPEC.md").is_file() and (root / "test_vectors.json").is_file()
    assert "RFC 6962" in data["seal_log"]["blob_root"]


def test_manifest_holds_no_event_data(root: Path) -> None:
    Builder(root, AUTHOR).node("secret-ish content")
    text = write_manifest(root, []).read_text(encoding="utf-8")
    assert "secret-ish content" not in text
    assert json.loads(text)["authors"] == []
