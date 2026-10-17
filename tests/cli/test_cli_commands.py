"""CLI-only behaviour of the archive subcommands.

Only what the SDK suite (``tests/sdk/``) cannot see belongs here: argparse
usage errors, flag validation, printed output and defaults applied on the CLI
side.  Event contents, chaining, blob storage and archive rules are covered by
the SDK tests.
"""

from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Any, Callable

import pytest

MARKDOWN_IS_KNOWN = mimetypes.guess_type("x.md")[0] == "text/markdown"

TEXT_PLAIN = "text/plain; charset=utf-8"


def _only_event(events: list[dict[str, Any]]) -> dict[str, Any]:
    assert len(events) == 1
    return events[0]


# --- create_node -----------------------------------------------------------------


def test_create_node_prints_the_new_node_id(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_cli("create_node", "--content", "an inline thought", "--title", "Thought")

    node_id = _only_event(base_events())["body"]["node_id"]
    assert f"Node created: {node_id}" in capsys.readouterr().out


@pytest.mark.skipif(
    not MARKDOWN_IS_KNOWN, reason="stdlib mimetypes does not map .md here"
)
def test_create_node_from_file_defaults_title_to_file_stem(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    sample_files: dict[str, Path],
) -> None:
    run_cli("create_node", "--content", str(sample_files["markdown"]))

    assert _only_event(base_events())["body"]["title"] == "limits"


def test_create_node_rejects_unsupported_file_without_writing(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    sample_files: dict[str, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        run_cli("create_node", "--content", str(sample_files["unsupported"]))
    assert excinfo.value.code == 1
    assert "ik: error: Unsupported archival media type" in capsys.readouterr().err
    assert base_events() == []


def test_create_node_ignores_media_type_flag_for_managed_nodes(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
) -> None:
    """Known limitation: --media-type is overridden for managed nodes."""
    run_cli("create_node", "--content", "still plain", "--media-type", "image/png")

    assert _only_event(base_events())["body"]["media_type"] == TEXT_PLAIN


def test_create_node_requires_content(run_cli: Callable[..., None]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        run_cli("create_node", "--title", "no body")
    assert excinfo.value.code == 2


@pytest.mark.parametrize(
    ("resource_type", "flag"), [("uri", "--uri"), ("local_file", "--path")]
)
def test_create_node_reference_requires_its_flag(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    capsys: pytest.CaptureFixture[str],
    resource_type: str,
    flag: str,
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        run_cli("create_node", "--resource-type", resource_type)
    assert excinfo.value.code == 2
    assert f"{flag} is required" in capsys.readouterr().err
    assert base_events() == []


# --- create_edge -----------------------------------------------------------------


@pytest.fixture
def two_nodes(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
) -> tuple[str, str]:
    """Create two managed nodes and return their UUIDs in creation order."""
    run_cli("create_node", "--content", "source node")
    run_cli("create_node", "--content", "target node")
    events = base_events()
    return events[0]["body"]["node_id"], events[1]["body"]["node_id"]


def test_create_edge_prints_the_new_edge_id(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    two_nodes: tuple[str, str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    capsys.readouterr()
    run_cli(
        "create_edge",
        "--content",
        "implies",
        "--source-node",
        "e1",
        "--target-node",
        "e2",
    )

    edge_id = base_events()[-1]["body"]["edge_id"]
    assert f"Edge created: {edge_id}" in capsys.readouterr().out


@pytest.mark.parametrize(
    "missing",
    ["--content", "--source-node", "--target-node"],
)
def test_create_edge_requires_all_three_flags(
    run_cli: Callable[..., None],
    two_nodes: tuple[str, str],
    missing: str,
) -> None:
    argv = {
        "--content": "text",
        "--source-node": "e1",
        "--target-node": "e2",
    }
    argv.pop(missing)
    flat = [item for pair in argv.items() for item in pair]
    with pytest.raises(SystemExit) as excinfo:
        run_cli("create_edge", *flat)
    assert excinfo.value.code == 2


# --- create_edge_tag -------------------------------------------------------------


def test_create_edge_tag_prints_the_new_tag_id(
    run_cli: Callable[..., None],
    meta_events: Callable[[], list[dict[str, Any]]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_cli("create_edge_tag", "--name", "topology", "--description", "About shapes")

    tag_id = _only_event(meta_events())["body"]["node_id"]
    assert f"Meta node created: {tag_id}" in capsys.readouterr().out


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


# --- set_tag ---------------------------------------------------------------------


@pytest.mark.parametrize("missing", ["--tag", "--id"])
def test_set_tag_requires_tag_and_id(
    run_cli: Callable[..., None],
    missing: str,
) -> None:
    argv = {"--tag": "m1", "--id": "e1"}
    argv.pop(missing)
    flat = [item for pair in argv.items() for item in pair]
    with pytest.raises(SystemExit) as excinfo:
        run_cli("set_tag", *flat)
    assert excinfo.value.code == 2


# --- transcribe ------------------------------------------------------------------


@pytest.mark.parametrize("network", ["base", "meta"])
def test_transcribe_prints_the_new_head_and_appends_to_that_log(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
    meta_events: Callable[[], list[dict[str, Any]]],
    capsys: pytest.CaptureFixture[str],
    network: str,
) -> None:
    run_cli("create_node", "--content", "n")
    run_cli("create_node_tag", "--name", "t", "--description", "d")
    capsys.readouterr()
    run_cli("transcribe", "--network", network, "--note", "checked")

    out = capsys.readouterr().out.strip()
    assert out.startswith("Transcription appended: sha256:")
    log, other = (
        (base_events(), meta_events())
        if network == "base"
        else (meta_events(), base_events())
    )
    body = log[-1]["body"]
    assert (body["event_type"], body["verified_count"], body["note"]) == (
        "transcription",
        1,
        "checked",
    )
    assert len(other) == 1  # the other log is untouched


def test_transcribe_defaults_to_base(
    run_cli: Callable[..., None],
    base_events: Callable[[], list[dict[str, Any]]],
) -> None:
    run_cli("create_node", "--content", "n")
    run_cli("transcribe")
    assert base_events()[-1]["body"]["event_type"] == "transcription"


def test_transcribe_an_empty_log_fails(
    run_cli: Callable[..., None], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        run_cli("transcribe", "--network", "meta")
    assert excinfo.value.code == 1
    assert "ik: error: Nothing to transcribe: the meta log is empty" in (
        capsys.readouterr().err
    )


def test_transcribe_rejects_an_unknown_network(run_cli: Callable[..., None]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        run_cli("transcribe", "--network", "other")
    assert excinfo.value.code == 2
