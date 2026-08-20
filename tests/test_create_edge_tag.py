"""Tests for ``ik create_edge_tag``."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import pytest


def test_create_edge_tag_writes_a_meta_event(
    run_cli: Callable[..., None],
    meta_events: Callable[[], list[dict[str, Any]]],
    base_events: Callable[[], list[dict[str, Any]]],
    blob_paths: Callable[[], list[Path]],
    author_public_key: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_cli("create_edge_tag", "--name", "topology", "--description", "About shapes")

    events = meta_events()
    assert len(events) == 1
    body = events[0]["body"]
    assert body["event_type"] == "create_edge_tag"
    assert body["body_type"] == "tag"
    assert body["name"] == "topology"
    assert body["description"] == "About shapes"
    assert body["node_id"]
    assert events[0]["header"]["prev_hash"] is None
    assert events[0]["header"]["author"] == author_public_key
    assert events[0]["signature"]

    # A tag is pure metadata: no base event and no blob.
    assert base_events() == []
    assert blob_paths() == []
    assert f"Meta node created: {body['node_id']}" in capsys.readouterr().out


def test_meta_log_lives_under_the_meta_subdirectory(
    run_cli: Callable[..., None],
    archive_root: Path,
) -> None:
    run_cli("create_edge_tag", "--name", "algebra", "--description", "Structures")

    assert list((archive_root / "meta" / "events").rglob("*ndjson"))
    assert not list((archive_root / "events").rglob("*ndjson"))


def test_successive_tags_chain_and_get_distinct_ids(
    run_cli: Callable[..., None],
    meta_events: Callable[[], list[dict[str, Any]]],
) -> None:
    run_cli("create_edge_tag", "--name", "first", "--description", "one")
    run_cli("create_edge_tag", "--name", "second", "--description", "two")

    events = meta_events()
    assert len(events) == 2
    assert events[0]["header"]["prev_hash"] is None
    assert events[1]["header"]["prev_hash"] is not None
    assert events[0]["body"]["node_id"] != events[1]["body"]["node_id"]


def test_duplicate_tag_names_are_allowed_but_distinct(
    run_cli: Callable[..., None],
    meta_events: Callable[[], list[dict[str, Any]]],
) -> None:
    run_cli("create_edge_tag", "--name", "same", "--description", "first meaning")
    run_cli("create_edge_tag", "--name", "same", "--description", "second meaning")

    events = meta_events()
    assert events[0]["body"]["name"] == events[1]["body"]["name"] == "same"
    assert events[0]["body"]["node_id"] != events[1]["body"]["node_id"]


def test_base_and_meta_chains_are_independent(
    run_cli: Callable[..., None],
    meta_events: Callable[[], list[dict[str, Any]]],
    base_events: Callable[[], list[dict[str, Any]]],
) -> None:
    run_cli("create_node", "--content", "a node")
    run_cli("create_edge_tag", "--name", "logic", "--description", "Inference")

    # The tag is the genesis of the meta chain even though the base log is not empty.
    assert meta_events()[0]["header"]["prev_hash"] is None
    assert len(base_events()) == 1


@pytest.mark.parametrize("missing", ["--name", "--description"])
def test_create_edge_tag_requires_name_and_description(
    run_cli: Callable[..., None],
    missing: str,
) -> None:
    argv = {"--name": "t", "--description": "d"}
    argv.pop(missing)
    flat = [item for pair in argv.items() for item in pair]
    with pytest.raises(SystemExit) as excinfo:
        run_cli("create_edge_tag", *flat)
    assert excinfo.value.code == 2
