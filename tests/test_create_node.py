"""Tests for ``ik create_node`` across the three resource types."""

from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Any, Callable

import pytest

MARKDOWN_IS_KNOWN = mimetypes.guess_type("x.md")[0] == "text/markdown"

TEXT_PLAIN = "text/plain; charset=utf-8"
TEXT_MARKDOWN = "text/markdown; charset=utf-8"


def _only_event(events: list[dict[str, Any]]) -> dict[str, Any]:
    assert len(events) == 1
    return events[0]


def test_managed_node_from_inline_content(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    blob_paths: Callable[[], list[Path]],
    author_public_key: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_cli("create_node", "--content", "an inline thought", "--title", "Thought")

    event = _only_event(base_events())
    body = event["body"]
    assert body["event_type"] == "create_node"
    assert body["body_type"] == "node"
    assert body["resource_type"] == "managed"
    assert body["media_type"] == TEXT_PLAIN
    assert body["title"] == "Thought"
    assert body["blob_hash"].startswith("sha256:")
    assert body["uri"] is None and body["path"] is None

    # Genesis event: no predecessor, signed by the current author.
    assert event["header"]["prev_hash"] is None
    assert event["header"]["author"] == author_public_key
    assert event["signature"]

    blobs = blob_paths()
    assert len(blobs) == 1
    assert blobs[0].read_bytes() == b"an inline thought"
    # The blob is stored under a two-level shard named by its own hash.
    digest = body["blob_hash"].removeprefix("sha256:")
    assert blobs[0].name == digest
    assert blobs[0].parent.name == digest[2:4]
    assert blobs[0].parent.parent.name == digest[:2]

    assert f"Node created: {body['node_id']}" in capsys.readouterr().out


@pytest.mark.skipif(not MARKDOWN_IS_KNOWN, reason="stdlib mimetypes does not map .md here")
def test_managed_node_from_markdown_file_infers_title_and_media_type(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    blob_paths: Callable[[], list[Path]],
    sample_files: dict[str, Path],
) -> None:
    markdown = sample_files["markdown"]
    run_cli("create_node", "--content", str(markdown))

    body = _only_event(base_events())["body"]
    assert body["media_type"] == TEXT_MARKDOWN
    # The title defaults to the file stem when --title is omitted.
    assert body["title"] == "limits"
    assert blob_paths()[0].read_bytes() == markdown.read_bytes()


def test_managed_node_from_binary_file_stores_raw_bytes(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    blob_paths: Callable[[], list[Path]],
    sample_files: dict[str, Path],
) -> None:
    png = sample_files["png"]
    run_cli("create_node", "--content", str(png))

    body = _only_event(base_events())["body"]
    assert body["media_type"] == "image/png"
    assert blob_paths()[0].read_bytes() == png.read_bytes()


def test_managed_node_rejects_unsupported_media_type(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    sample_files: dict[str, Path],
) -> None:
    with pytest.raises(ValueError, match="Unsupported archival media type"):
        run_cli("create_node", "--content", str(sample_files["unsupported"]))
    assert base_events() == []


def test_managed_node_ignores_media_type_flag(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
) -> None:
    """Known limitation: --media-type is overridden for managed nodes."""
    run_cli("create_node", "--content", "still plain", "--media-type", "image/png")

    assert _only_event(base_events())["body"]["media_type"] == TEXT_PLAIN


def test_managed_node_requires_content(run_cli: Callable[..., None]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        run_cli("create_node", "--title", "no body")
    assert excinfo.value.code == 2


def test_uri_node_records_reference_without_blob(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    blob_paths: Callable[[], list[Path]],
) -> None:
    run_cli(
        "create_node",
        "--resource-type",
        "uri",
        "--uri",
        "https://example.org/paper",
        "--title",
        "A paper",
        "--media-type",
        "application/pdf; profile=pdfa",
    )

    body = _only_event(base_events())["body"]
    assert body["resource_type"] == "uri"
    assert body["uri"] == "https://example.org/paper"
    assert body["media_type"] == "application/pdf; profile=pdfa"
    assert body["blob_hash"] is None
    assert blob_paths() == []


def test_uri_node_requires_uri(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
) -> None:
    with pytest.raises(ValueError, match="--uri is required"):
        run_cli("create_node", "--resource-type", "uri")
    assert base_events() == []


def test_local_file_node_records_fingerprint_without_copying(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    blob_paths: Callable[[], list[Path]],
    sample_files: dict[str, Path],
) -> None:
    plain = sample_files["plain"]
    run_cli("create_node", "--resource-type", "local_file", "--path", str(plain))

    body = _only_event(base_events())["body"]
    assert body["resource_type"] == "local_file"
    assert body["path"] == str(plain.resolve())
    assert body["file_size"] == plain.stat().st_size
    assert body["file_hash"].startswith("sha256:")
    assert body["last_verified"] is not None
    assert body["media_type"] == TEXT_PLAIN
    assert body["blob_hash"] is None
    # local_file nodes are references: nothing is imported into the blob store.
    assert blob_paths() == []


def test_local_file_node_rejects_missing_path(
    run_cli: Callable[..., None],
    tmp_path: Path,
    base_events: Callable[[], list[dict[str, Any]]],
) -> None:
    absent = tmp_path / "inputs" / "nope.txt"
    with pytest.raises(ValueError, match="Local file does not exist"):
        run_cli("create_node", "--resource-type", "local_file", "--path", str(absent))
    assert base_events() == []


def test_successive_nodes_chain_and_keep_distinct_ids(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
) -> None:
    run_cli("create_node", "--content", "first")
    run_cli("create_node", "--content", "second")

    events = base_events()
    assert len(events) == 2
    assert events[0]["header"]["prev_hash"] is None
    assert events[1]["header"]["prev_hash"] is not None
    assert events[0]["body"]["node_id"] != events[1]["body"]["node_id"]


def test_identical_content_is_deduplicated_in_the_blob_store(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    blob_paths: Callable[[], list[Path]],
) -> None:
    run_cli("create_node", "--content", "same text")
    run_cli("create_node", "--content", "same text")

    events = base_events()
    assert events[0]["body"]["blob_hash"] == events[1]["body"]["blob_hash"]
    assert len(blob_paths()) == 1
