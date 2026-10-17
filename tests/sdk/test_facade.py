"""End-to-end tests of the public SDK facade (``import indiek``)."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import pytest

import indiek
from indiek import (
    Archive,
    ArchiveRuleError,
    Author,
    AuthorshipError,
    IndexedItem,
    IngestResult,
    IntegrityError,
    ItemKind,
    MediaType,
    ResourceType,
    UnknownItemError,
)

AUTHOR = Author.from_seed_hex("bb" * 32)  # public test vector, not a secret


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "archive"


@pytest.fixture
def ik(root: Path) -> Archive:
    return Archive.open(root, author=AUTHOR)


def test_public_names() -> None:
    for name in indiek.__all__:
        assert hasattr(indiek, name), name
    assert {"Archive", "Author", "IntegrityError", "MediaType"} <= set(indiek.__all__)
    assert isinstance(indiek.__version__, str)


def test_open_missing_folder_is_an_empty_archive(root: Path) -> None:
    ik = Archive.open(root)
    assert (ik.head, ik.meta_head, ik.author) == (None, None, None)
    assert list(ik.events()) == [] and list(ik.events("meta")) == []
    assert ik.path == root


def test_writes_refresh_the_index(ik: Archive) -> None:
    a = ik.create_node("a")
    assert ik.index.get("e1").id == a
    b = ik.create_node("b", title="B")
    edge = ik.create_edge("e1", "e2", "a to b")  # aliases usable immediately
    assert ik.index.get("e3").id == edge
    item = ik.index.get(b)
    assert isinstance(item, IndexedItem) and item.body["title"] == "B"
    assert ik.head is not None and ik.head == ik.index.head


def test_create_node_text_defaults_to_plain_and_never_reads_paths(
    ik: Archive, tmp_path: Path
) -> None:
    existing = tmp_path / "exists.txt"
    existing.write_text("file body", encoding="utf-8")
    ik.create_node(str(existing))
    body = ik.index.get("e1").body
    assert body["media_type"] == MediaType.TEXT_PLAIN.value
    assert ik.index.store.blobs.get_text(body["blob_hash"]) == str(existing)


def test_create_node_markdown_and_bytes(ik: Archive) -> None:
    ik.create_node("# t", media_type=MediaType.TEXT_MARKDOWN)
    ik.create_node(b"\x89PNG", media_type=MediaType.IMAGE_PNG)
    assert ik.index.get("e1").body["media_type"] == MediaType.TEXT_MARKDOWN.value
    assert ik.index.get("e2").body["media_type"] == "image/png"


def test_create_node_bytes_require_media_type(ik: Archive) -> None:
    with pytest.raises(ArchiveRuleError, match="media_type"):
        ik.create_node(b"\x00")


def test_create_node_managed_requires_content(ik: Archive) -> None:
    with pytest.raises(ArchiveRuleError, match="content"):
        ik.create_node()


def test_create_uri_and_local_file_nodes(ik: Archive, tmp_path: Path) -> None:
    local = tmp_path / "page.png"
    local.write_bytes(b"\x89PNG")
    ik.create_node(resource_type=ResourceType.URI, uri="https://x.org", title="X")
    ik.create_node(resource_type=ResourceType.LOCAL_FILE, path=local)
    assert ik.index.get("e1").body["uri"] == "https://x.org"
    assert ik.index.get("e2").body["path"] == str(local.resolve())


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"resource_type": ResourceType.URI}, "uri"),
        ({"resource_type": ResourceType.LOCAL_FILE}, "path"),
    ],
)
def test_reference_nodes_require_their_field(
    ik: Archive, kwargs: dict[str, object], message: str
) -> None:
    with pytest.raises(ArchiveRuleError, match=message):
        ik.create_node(**kwargs)  # type: ignore[arg-type]


def test_supersedes(ik: Archive) -> None:
    ik.create_node("a", title="A")
    ik.create_node("b")
    ik.create_edge("e1", "e2", "r")
    ik.supersede_node("e1", "a2")
    ik.supersede_edge("e3", "r2")
    assert ik.index.get("e1").body["title"] == "A"
    assert ik.index.get("e3").body["event_type"] == "supersede_edge"


def test_tags(ik: Archive) -> None:
    node = ik.create_node("n")
    tag = ik.create_tag("theorem", "A proven statement", kind="node")
    assert ik.index.get("m1").kind is ItemKind.NODE_TAG
    ik.set_tag("m1", "e1")
    assert ik.index.items[node].tags == {tag}


def test_ingest_export_manifest(ik: Archive, root: Path, tmp_path: Path) -> None:
    folder = tmp_path / "in"
    folder.mkdir()
    (folder / "a.txt").write_text("alpha", encoding="utf-8")
    edges = tmp_path / "edges.csv"
    edges.write_text("e1,e1,self\n", encoding="utf-8")
    result = ik.ingest(input_folder=folder, edges_file=edges)
    assert isinstance(result, IngestResult)
    assert (len(result.node_ids), len(result.edge_ids)) == (1, 1)
    assert ik.index.get("e2").kind is ItemKind.EDGE

    out = ik.export_graphml(tmp_path / "g.graphml")
    assert "<node " in out.read_text(encoding="utf-8")

    manifest = ik.write_manifest()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["authors"][0]["public_key"] == AUTHOR.public_key_hex


def test_read_only_archive_refuses_writes(root: Path) -> None:
    Archive.open(root, author=AUTHOR).create_node("n")
    ik = Archive.open(root)
    with pytest.raises(AuthorshipError, match="An author is required to write"):
        ik.create_node("x")
    assert json.loads(ik.write_manifest().read_text(encoding="utf-8"))["authors"] == []


def test_events_iterates_both_networks(ik: Archive) -> None:
    ik.create_node("n")
    ik.create_tag("t", "d", kind="edge")
    assert [e["body"]["event_type"] for e in ik.events()] == ["create_node"]
    assert [e["body"]["event_type"] for e in ik.events("meta")] == ["create_edge_tag"]
    with pytest.raises(ValueError, match="network"):
        list(ik.events("other"))  # type: ignore[arg-type]


def test_errors_surface_unchanged(ik: Archive) -> None:
    with pytest.raises(UnknownItemError):
        ik.create_edge("e1", "e2", "x")


def test_open_detects_tampering(root: Path) -> None:
    Archive.open(root, author=AUTHOR).create_node("n")
    (path,) = (root / "events").rglob("*ndjson")
    event = json.loads(path.read_text(encoding="utf-8"))
    event["body"]["title"] = "forged"
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    with pytest.raises(IntegrityError, match="Data tampered or bad author!"):
        Archive.open(root)


def test_sdk_walkthrough(ik: Archive) -> None:
    """The README example, SDK-only."""
    e1 = ik.create_node("Gödel's incompleteness theorem")
    ik.create_node("statement", title="statement")
    ik.create_edge("e2", "e1", "states")
    ik.supersede_node(e1, "Gödel's *first* incompleteness theorem")
    theorem = ik.create_tag("theorem", "A proven statement", kind="node")
    proof = ik.create_tag("proof", "Proof relation", kind="edge")
    ik.set_tag(theorem, e1)
    ik.set_tag(proof, "e3")
    assert [ik.index.alias_of(i) for i in (theorem, proof)] == ["m1", "m2"]
    assert isinstance(ik.index.resolve("m6"), UUID)
    assert ik.index.items[e1].tags == {theorem}
