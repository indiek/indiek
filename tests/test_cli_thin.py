"""CLI-only behaviour (CLIPYPI:SDK-REORG-CLI-THIN): logging, bootstrap commands, keys."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Callable

import pytest

from indiek import ArchiveRuleError, Author, AuthorshipError
from indiek import cli as ik_cli

SEED_LINE = re.compile(r"^IK_AUTHOR_PRIVATE_KEY=([0-9a-f]{64})$", re.MULTILINE)


@pytest.fixture
def ik(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Callable[..., None]:
    """Run ``ik`` with exactly the given environment (``None`` unsets a variable)."""
    dotenv = tmp_path / "absent.env"

    def _run(*argv: str, env: dict[str, str | None], dot_env: Path = dotenv) -> None:
        for name in ("IK_ARCHIVE_PATH", "IK_AUTHOR_PRIVATE_KEY"):
            monkeypatch.setenv(name, "placeholder")  # so monkeypatch restores it
            value = env.get(name)
            if value is None:
                monkeypatch.delenv(name)
            else:
                monkeypatch.setenv(name, value)
        monkeypatch.setattr("sys.argv", ["ik", "--dot-env", str(dot_env), *argv])
        ik_cli.main()

    return _run


@pytest.fixture
def env(archive_root: Path, author_seed_hex: str) -> dict[str, str | None]:
    return {"IK_ARCHIVE_PATH": str(archive_root), "IK_AUTHOR_PRIVATE_KEY": author_seed_hex}


# --- logging -----------------------------------------------------------------


def test_logs_go_to_stderr_and_results_to_stdout(
    ik: Callable[..., None],
    env: dict[str, str | None],
    capsys: pytest.CaptureFixture[str],
) -> None:
    ik("create_node", "--content", "a node", env=env)
    ik("create_edge_tag", "--name", "t", "--description", "d", env=env)
    capsys.readouterr()
    with pytest.raises(ArchiveRuleError):
        ik("set_tag", "--tag", "m1", "--id", "e1", env=env)  # WARNING, then error
    captured = capsys.readouterr()
    assert "remains in the meta log" in captured.err
    assert captured.out == ""


def test_default_level_keeps_stderr_quiet_on_success(
    ik: Callable[..., None],
    env: dict[str, str | None],
    capsys: pytest.CaptureFixture[str],
) -> None:
    ik("create_node", "--content", "a node", env=env)
    captured = capsys.readouterr()
    assert captured.out.startswith("Node created: ")
    assert captured.err == ""


@pytest.mark.parametrize(
    ("given", "level"),
    [("debug", logging.DEBUG), ("Info", logging.INFO), ("ERROR", logging.ERROR)],
)
def test_logging_level_is_case_insensitive(
    ik: Callable[..., None], env: dict[str, str | None], given: str, level: int
) -> None:
    ik("--logging-level", given, "read", "--mini", env=env)
    assert logging.getLogger().level == level


def test_debug_logs_reach_stderr(
    ik: Callable[..., None],
    env: dict[str, str | None],
    capsys: pytest.CaptureFixture[str],
) -> None:
    ik("--logging-level", "debug", "read", "--mini", env=env)
    assert "ARCHIVE INTEGRITY VERIFIED" in capsys.readouterr().err


def test_unknown_logging_level_is_a_usage_error(
    ik: Callable[..., None], env: dict[str, str | None]
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        ik("--logging-level", "loud", "read", env=env)
    assert excinfo.value.code == 2


# --- config --------------------------------------------------------------------


def test_config_works_with_no_environment(
    ik: Callable[..., None], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ik("config", env={})
    assert capsys.readouterr().out.strip() == "IK_ARCHIVE_PATH is not set"


def test_config_shows_value_from_dotenv(
    ik: Callable[..., None], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dotenv = tmp_path / "cfg.env"
    dotenv.write_text("IK_ARCHIVE_PATH=/from/dotenv\n", encoding="utf-8")
    ik("config", env={}, dot_env=dotenv)
    assert capsys.readouterr().out.strip() == "IK_ARCHIVE_PATH=/from/dotenv"


def test_config_sets_path_without_key_or_archive(
    ik: Callable[..., None], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dotenv = tmp_path / "cfg.env"
    ik("config", "--set-archive-path", "/x/y", env={}, dot_env=dotenv)
    assert dotenv.read_text(encoding="utf-8").strip() == "IK_ARCHIVE_PATH='/x/y'"
    assert capsys.readouterr().out.strip().splitlines() == [
        "IK_ARCHIVE_PATH is not set",
        "IK_ARCHIVE_PATH=/x/y",
    ]
    assert not Path("/x/y").exists()


# --- keygen --------------------------------------------------------------------


def test_keygen_prints_a_dotenv_line_and_public_key(
    ik: Callable[..., None], capsys: pytest.CaptureFixture[str]
) -> None:
    ik("keygen", env={})
    captured = capsys.readouterr()
    match = SEED_LINE.search(captured.out)
    assert match is not None
    assert Author.from_seed_hex(match.group(1)).public_key_hex in captured.err


def test_keygen_gives_distinct_keys(
    ik: Callable[..., None], capsys: pytest.CaptureFixture[str]
) -> None:
    ik("keygen", env={})
    ik("keygen", env={})
    assert len(set(SEED_LINE.findall(capsys.readouterr().out))) == 2


def test_keygen_write_stores_seed_without_printing_it(
    ik: Callable[..., None], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dotenv = tmp_path / "new.env"
    ik("keygen", "--write", env={}, dot_env=dotenv)
    match = SEED_LINE.search(dotenv.read_text(encoding="utf-8").replace("'", ""))
    assert match is not None
    captured = capsys.readouterr()
    assert match.group(1) not in captured.out + captured.err
    assert Author.from_seed_hex(match.group(1)).public_key_hex in captured.err
    assert str(dotenv) in captured.err


def test_keygen_write_refuses_to_overwrite(
    ik: Callable[..., None], tmp_path: Path
) -> None:
    dotenv = tmp_path / "existing.env"
    dotenv.write_text("IK_AUTHOR_PRIVATE_KEY=" + "11" * 32 + "\n", encoding="utf-8")
    with pytest.raises(SystemExit) as excinfo:
        ik("keygen", "--write", env={}, dot_env=dotenv)
    assert excinfo.value.code == 1
    assert "11" * 32 in dotenv.read_text(encoding="utf-8")


def test_keygen_write_force_overwrites(ik: Callable[..., None], tmp_path: Path) -> None:
    dotenv = tmp_path / "existing.env"
    dotenv.write_text("IK_AUTHOR_PRIVATE_KEY=" + "11" * 32 + "\n", encoding="utf-8")
    ik("keygen", "--write", "--force", env={}, dot_env=dotenv)
    assert "11" * 32 not in dotenv.read_text(encoding="utf-8")


# --- keys and read-only commands ---------------------------------------------------


def test_read_only_commands_need_no_key(
    ik: Callable[..., None],
    env: dict[str, str | None],
    archive_root: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ik("create_node", "--content", "a node", env=env)
    read_only = {**env, "IK_AUTHOR_PRIVATE_KEY": None}
    ik("read", "--mini", env=read_only)
    ik("export", "--output-path", str(tmp_path / "g.graphml"), env=read_only)
    ik("manifest", env=read_only)
    assert "Events Log" in capsys.readouterr().out
    assert (tmp_path / "g.graphml").exists()
    manifest = json.loads((archive_root / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["authors"] == []


def test_write_without_key_is_refused(
    ik: Callable[..., None], env: dict[str, str | None], base_events: Callable[[], list]
) -> None:
    with pytest.raises(AuthorshipError, match="An author is required"):
        ik("create_node", "--content", "x", env={**env, "IK_AUTHOR_PRIVATE_KEY": None})
    assert base_events() == []


def test_bad_key_is_still_rejected(ik: Callable[..., None], env: dict[str, str | None]) -> None:
    with pytest.raises(ValueError, match="Invalid key length"):
        ik("read", env={**env, "IK_AUTHOR_PRIVATE_KEY": "ab" * 16})


def test_archive_commands_need_an_archive_path(ik: Callable[..., None]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        ik("read", env={})
    assert excinfo.value.code == 2
