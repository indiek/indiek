"""Unit tests for ``indiek.ops.events`` and ``indiek.ops.nodes``."""

from __future__ import annotations

import hashlib
import mimetypes
from pathlib import Path
from uuid import UUID, uuid7

import pytest
from _builders import Builder

from indiek.core.archive import ArchiveStore
from indiek.core.author import Author
from indiek.core.errors import ArchiveRuleError, UnknownItemError
from indiek.core.index import ArchiveIndex, ItemKind
from indiek.core.models import EventModel, MediaType, MetaEventModel, MetaEventType, Node, Tag
from indiek.core.signing import verify_body
from indiek.ops import events, nodes

AUTHOR = Author.from_seed_hex("66" * 32)  # public test vector, not a secret
MARKDOWN_IS_KNOWN = mimetypes.guess_type("x.md")[0] == "text/markdown"


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "archive"


@pytest.fixture
def files(tmp_path: Path) -> dict[str, Path]:
    directory = tmp_path / "inputs"
    directory.mkdir()
    paths = {
        "txt": directory / "note.txt",
        "md": directory / "limits.md",
        "png": directory / "scan.png",
        "csv": directory / "data.csv",
    }
    paths["txt"].write_text("plain body", encoding="utf-8")
    paths["md"].write_text("# Limits\n", encoding="utf-8")
    paths["png"].write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 8)
    paths["csv"].write_text("a,b\n", encoding="utf-8")
    return paths


def _index(root: Path) -> ArchiveIndex:
    return ArchiveIndex(ArchiveStore.open(root))


# --- ops.events ----------------------------------------------------------------


def _node_body(index: ArchiveIndex, text: str) -> Node:
    digest = index.store.blobs.put(text)
    return Node(blob_hash=digest, media_type=MediaType.TEXT_PLAIN)


def test_append_base_chains_onto_the_current_head(root: Path) -> None:
    first = events.append_base(_index(root), AUTHOR, _node_body(_index(root), "one"))
    assert isinstance(first, EventModel)
    assert first.header.prev_hash is None
    assert first.header.author == AUTHOR.public_key_hex
    assert verify_body(first.body, first.signature or "", AUTHOR.public_key_hex)

    index = _index(root)
    second = events.append_base(index, AUTHOR, _node_body(index, "two"))
    assert second.header.prev_hash == index.head
    assert _index(root).store.base_count == 2


def test_append_meta_uses_its_own_chain(root: Path) -> None:
    Builder(root, AUTHOR).node("base")
    tag = Tag(name="t", description="d", event_type=MetaEventType.CREATE_NODE_TAG)
    event = events.append_meta(_index(root), AUTHOR, tag)
    assert isinstance(event, MetaEventModel)
    assert event.header.prev_hash is None
    store = _index(root).store
    assert (store.base_count, store.meta_count) == (1, 1)


# --- content detection -----------------------------------------------------------


def test_extract_reads_text_files_as_text(files: dict[str, Path]) -> None:
    assert nodes.extract_content_and_mime(str(files["txt"])) == (
        "plain body",
        MediaType.TEXT_PLAIN,
    )


@pytest.mark.skipif(not MARKDOWN_IS_KNOWN, reason="stdlib mimetypes does not map .md")
def test_extract_detects_markdown(files: dict[str, Path]) -> None:
    assert nodes.extract_content_and_mime(str(files["md"]))[1] is MediaType.TEXT_MARKDOWN


def test_extract_reads_binary_files_as_bytes(files: dict[str, Path]) -> None:
    content, media_type = nodes.extract_content_and_mime(str(files["png"]))
    assert content == files["png"].read_bytes()
    assert media_type is MediaType.IMAGE_PNG


def test_extract_treats_non_paths_as_literal_text() -> None:
    assert nodes.extract_content_and_mime("just words") == ("just words", MediaType.TEXT_PLAIN)


def test_detect_rejects_unsupported_types(files: dict[str, Path]) -> None:
    with pytest.raises(ArchiveRuleError, match="Unsupported archival media type"):
        nodes.detect_media_type(files["csv"])


# --- node creation ---------------------------------------------------------------


def test_create_managed_text_node(root: Path) -> None:
    node_id = nodes.create_managed_node(
        _index(root), AUTHOR, "Gödel", MediaType.TEXT_PLAIN, title="G"
    )
    assert isinstance(node_id, UUID)
    item = _index(root).get("e1")
    assert (item.id, item.kind, item.author) == (node_id, ItemKind.NODE, AUTHOR.public_key_hex)
    body = item.body
    assert (body["resource_type"], body["media_type"], body["title"]) == (
        "managed",
        MediaType.TEXT_PLAIN.value,
        "G",
    )
    digest = hashlib.sha256("Gödel".encode("utf-8")).hexdigest()
    assert body["blob_hash"] == f"sha256:{digest}"
    assert _index(root).store.blobs.get(digest) == "Gödel".encode("utf-8")


def test_create_managed_binary_node(root: Path, files: dict[str, Path]) -> None:
    data = files["png"].read_bytes()
    nodes.create_managed_node(_index(root), AUTHOR, data, MediaType.IMAGE_PNG)
    body = _index(root).get("e1").body
    assert body["media_type"] == "image/png" and body["title"] is None
    assert _index(root).store.blobs.get(body["blob_hash"]) == data


def test_create_uri_node_writes_no_blob(root: Path) -> None:
    nodes.create_uri_node(
        _index(root),
        AUTHOR,
        "https://example.org/paper",
        title="Paper",
        media_type=MediaType.APPLICATION_PDF_A,
    )
    index = _index(root)
    body = index.get("e1").body
    assert (body["resource_type"], body["uri"], body["blob_hash"]) == (
        "uri",
        "https://example.org/paper",
        None,
    )
    assert body["media_type"] == MediaType.APPLICATION_PDF_A.value
    assert index.store.blobs.iter_hashes() == []


def test_create_local_file_node_records_fingerprint(root: Path, files: dict[str, Path]) -> None:
    nodes.create_local_file_node(_index(root), AUTHOR, files["txt"])
    index = _index(root)
    body = index.get("e1").body
    data = files["txt"].read_bytes()
    assert body["resource_type"] == "local_file"
    assert body["path"] == str(files["txt"].resolve())
    assert body["file_size"] == len(data)
    assert body["file_hash"] == "sha256:" + hashlib.sha256(data).hexdigest()
    assert body["last_verified"] is not None
    assert body["title"] == "note"
    assert body["media_type"] == MediaType.TEXT_PLAIN.value
    assert index.store.blobs.iter_hashes() == []


def test_create_local_file_node_rejects_missing_file(root: Path, tmp_path: Path) -> None:
    with pytest.raises(ArchiveRuleError, match="Local file does not exist"):
        nodes.create_local_file_node(_index(root), AUTHOR, tmp_path / "absent.txt")
    assert _index(root).store.base_count == 0


def test_create_local_file_node_rejects_unsupported_type(
    root: Path, files: dict[str, Path]
) -> None:
    with pytest.raises(ArchiveRuleError, match="Unsupported archival media type"):
        nodes.create_local_file_node(_index(root), AUTHOR, files["csv"])


# --- supersede ---------------------------------------------------------------------


def test_supersede_node_keeps_title_and_alias(root: Path) -> None:
    node_id = Builder(root, AUTHOR).node("v1", title="T")
    assert nodes.supersede_node(_index(root), AUTHOR, "e1", "v2") == node_id
    item = _index(root).get("e1")
    assert item.id == node_id
    assert item.body["event_type"] == "supersede_node"
    assert item.body["title"] == "T"
    assert item.body["media_type"] == MediaType.TEXT_MARKDOWN.value
    assert _index(root).store.blobs.get_text(item.body["blob_hash"]) == "v2"


def test_supersede_node_can_replace_title(root: Path) -> None:
    Builder(root, AUTHOR).node("v1", title="T")
    nodes.supersede_node(_index(root), AUTHOR, "e1", "v2", title="T2")
    assert _index(root).get("e1").body["title"] == "T2"


def test_supersede_node_rejects_edges(root: Path) -> None:
    build = Builder(root, AUTHOR)
    build.edge(build.node("a"), build.node("b"), "ab")
    with pytest.raises(UnknownItemError, match="does not reference a base-network node"):
        nodes.supersede_node(_index(root), AUTHOR, "e3", "x")


@pytest.mark.parametrize("ref", ["e9", "garbage"])
def test_supersede_node_rejects_unknown_ids(root: Path, ref: str) -> None:
    with pytest.raises(UnknownItemError, match="does not exist in this archive"):
        nodes.supersede_node(_index(root), AUTHOR, ref, "x")


def test_supersede_node_rejects_unknown_uuid(root: Path) -> None:
    with pytest.raises(UnknownItemError, match="does not exist in this archive"):
        nodes.supersede_node(_index(root), AUTHOR, str(uuid7()), "x")
