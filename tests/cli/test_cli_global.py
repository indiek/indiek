"""Tests for the global ``ik`` options and the per-invocation integrity check."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable

import pytest

from indiek import cli as ik_cli


def _rewrite_events(
    archive_root: Path, mutate: Callable[[list[dict[str, Any]]], None]
) -> None:
    """Apply ``mutate`` to the base events, rewriting each NDJSON file in place."""
    for path in sorted((archive_root / "events").rglob("*ndjson")):
        events = [json.loads(line) for line in path.read_text("utf-8").splitlines()]
        mutate(events)
        path.write_text(
            "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
        )


def _assert_cli_error(
    capsys: pytest.CaptureFixture[str], run: Callable[[], None], message: str
) -> None:
    """The command fails with exit 1 and a one-line ``ik: error:`` on stderr."""
    with pytest.raises(SystemExit) as excinfo:
        run()
    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "ik: error:" in err
    assert message in err
    assert "Traceback" not in err


def test_dot_env_supplies_archive_path_and_key(
    tmp_path: Path,
    archive_root: Path,
    author_seed_hex: str,
    author_public_key: str,
    base_events: Callable[[], list[dict[str, Any]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dotenv = tmp_path / "test.env"
    dotenv.write_text(
        f"IK_ARCHIVE_PATH={archive_root}\nIK_AUTHOR_PRIVATE_KEY={author_seed_hex}\n",
        encoding="utf-8",
    )
    # setenv first so monkeypatch restores the environment that load_dotenv mutates.
    for name in ("IK_ARCHIVE_PATH", "IK_AUTHOR_PRIVATE_KEY"):
        monkeypatch.setenv(name, "placeholder")
        monkeypatch.delenv(name)
    monkeypatch.setattr(
        "sys.argv",
        [
            "ik",
            "--dot-env",
            str(dotenv),
            "--logging-level",
            "CRITICAL",
            "create_node",
            "--content",
            "from dotenv",
        ],
    )

    ik_cli.main()

    events = base_events()
    assert len(events) == 1
    assert events[0]["header"]["author"] == author_public_key


def test_logging_level_sets_root_logger(
    tmp_path: Path,
    archive_root: Path,
    author_seed_hex: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IK_ARCHIVE_PATH", str(archive_root))
    monkeypatch.setenv("IK_AUTHOR_PRIVATE_KEY", author_seed_hex)
    monkeypatch.setattr(
        "sys.argv",
        [
            "ik",
            "--dot-env",
            str(tmp_path / "absent.env"),
            "--logging-level",
            "DEBUG",
            "create_edge_tag",
            "--name",
            "t",
            "--description",
            "d",
        ],
    )

    ik_cli.main()

    assert logging.getLogger().level == logging.DEBUG


def test_tampered_signature_is_detected(
    run_cli: Callable[..., None],
    archive_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_cli("create_node", "--content", "original")

    def flip_signature(events: list[dict[str, Any]]) -> None:
        prefix, digits = events[0]["signature"].split(":")
        flipped = "0" if digits[0] != "0" else "1"
        events[0]["signature"] = f"{prefix}:{flipped}{digits[1:]}"

    _rewrite_events(archive_root, flip_signature)

    _assert_cli_error(
        capsys,
        lambda: run_cli("create_node", "--content", "next"),
        "Data tampered or bad author!",
    )


def test_broken_chain_is_detected(
    run_cli: Callable[..., None],
    archive_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_cli("create_node", "--content", "first")
    run_cli("create_node", "--content", "second")

    def break_chain(events: list[dict[str, Any]]) -> None:
        events[1]["header"]["prev_hash"] = "sha256:" + "0" * 64

    _rewrite_events(archive_root, break_chain)

    _assert_cli_error(
        capsys, lambda: run_cli("create_node", "--content", "third"), "Chain broken!"
    )


def test_corrupted_blob_is_detected(
    run_cli: Callable[..., None],
    blob_paths: Callable[[], list[Path]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_cli("create_node", "--content", "blob body")
    (blob,) = blob_paths()
    blob.write_bytes(blob.read_bytes() + b" tampered")

    _assert_cli_error(
        capsys,
        lambda: run_cli("create_node", "--content", "next"),
        "File corrupted or missing!",
    )
