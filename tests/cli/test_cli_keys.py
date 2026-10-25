"""DESKTOP:KEY-ONBOARDING (CLI side): ``ik`` shares the OS-keychain identity with the app.

``ik keygen --keychain``, ``ik key_show``, ``ik key_backup``, ``ik key_restore``; every archive
command signs with ``IK_AUTHOR_PRIVATE_KEY`` if set, else with the keychain key.
"""

from __future__ import annotations

import json
import stat
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from indiek import Author, keys
from indiek import cli as ik_cli
from indiek.keys import KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE

PASSWORD = "correct horse battery"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch: pytest.MonkeyPatch) -> None:
    from nacl import pwhash

    monkeypatch.setattr(keys, "BACKUP_OPSLIMIT", pwhash.argon2id.OPSLIMIT_MIN)
    monkeypatch.setattr(keys, "BACKUP_MEMLIMIT", pwhash.argon2id.MEMLIMIT_MIN)


@pytest.fixture
def ik(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, archive_root: Path
) -> Callable[..., None]:
    """Run ``ik`` with NO key in the environment and no dotenv file."""
    monkeypatch.delenv("IK_AUTHOR_PRIVATE_KEY", raising=False)
    monkeypatch.setenv("IK_ARCHIVE_PATH", str(archive_root))

    def _run(*argv: str) -> None:
        monkeypatch.setattr(
            "sys.argv",
            [
                "ik",
                "--dot-env",
                str(tmp_path / "absent.env"),
                "--logging-level",
                "CRITICAL",
                *argv,
            ],
        )
        ik_cli.main()

    return _run


@pytest.fixture
def passwords(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Answers given to successive getpass prompts."""
    answers: list[str] = []
    monkeypatch.setattr(ik_cli.getpass, "getpass", lambda prompt="": answers.pop(0))
    yield answers
    assert answers == [], "unused password answers"


def _fails(
    capsys: pytest.CaptureFixture[str], run: Callable[[], None], message: str
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        run()
    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "ik: error:" in err and message in err and "Traceback" not in err


def _stored(memory_keyring: Any) -> Author:
    return Author.from_seed_hex(
        memory_keyring.store[(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)]
    )


# -- keygen --keychain / key_show -------------------------------------------------------


def test_keygen_into_the_keychain(
    ik: Callable[..., None], memory_keyring: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    ik("keygen", "--keychain")
    out, err = capsys.readouterr()
    stored = _stored(memory_keyring)
    assert out == ""  # the seed is never printed
    assert stored.seed_hex not in err
    assert f"Public key: {stored.public_key_hex}" in err
    ik("key_show")
    out = capsys.readouterr().out
    assert stored.public_key_hex in out and "keychain" in out


def test_keygen_keychain_refuses_to_replace_without_force(
    ik: Callable[..., None], memory_keyring: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    ik("keygen", "--keychain")
    first = _stored(memory_keyring)
    capsys.readouterr()
    _fails(
        capsys, lambda: ik("keygen", "--keychain"), "already holds an IndieK author key"
    )
    assert _stored(memory_keyring).seed_hex == first.seed_hex
    ik("keygen", "--keychain", "--force")
    assert _stored(memory_keyring).seed_hex != first.seed_hex


def test_keygen_keychain_and_write_are_exclusive(ik: Callable[..., None]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        ik("keygen", "--keychain", "--write")
    assert excinfo.value.code == 2


def test_key_show_reports_env_first(
    ik: Callable[..., None],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    keys.store_in_keychain(Author.generate())
    env = Author.generate()
    monkeypatch.setenv("IK_AUTHOR_PRIVATE_KEY", env.seed_hex)
    ik("key_show")
    out = capsys.readouterr().out
    assert env.public_key_hex in out and "IK_AUTHOR_PRIVATE_KEY" in out


def test_key_show_without_any_key(
    ik: Callable[..., None], capsys: pytest.CaptureFixture[str]
) -> None:
    _fails(capsys, lambda: ik("key_show"), "No author key")


# -- archive commands sign with the keychain key --------------------------------------------


def test_archive_commands_sign_with_the_keychain_key(
    ik: Callable[..., None],
    memory_keyring: Any,
    base_events: Callable[[], list[dict[str, Any]]],
) -> None:
    ik("keygen", "--keychain")
    ik("create_node", "--content", "signed by the keychain key")
    [event] = base_events()
    assert event["header"]["author"] == _stored(memory_keyring).public_key_hex


def test_without_any_key_archive_writes_still_fail_cleanly(
    ik: Callable[..., None], capsys: pytest.CaptureFixture[str]
) -> None:
    _fails(capsys, lambda: ik("create_node", "--content", "x"), "author is required")


# -- encrypted backups ---------------------------------------------------------------


def test_backup_and_restore_into_the_keychain(
    ik: Callable[..., None],
    memory_keyring: Any,
    passwords: list[str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ik("keygen", "--keychain")
    original = _stored(memory_keyring)
    backup = tmp_path / "me.ikkey"
    passwords.extend([PASSWORD, PASSWORD])
    ik("key_backup", "--out", str(backup))
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert json.loads(backup.read_text())["public_key"] == original.public_key_hex
    assert original.seed_hex not in backup.read_text()
    memory_keyring.store.clear()
    passwords.append(PASSWORD)
    ik("key_restore", str(backup), "--keychain")
    assert _stored(memory_keyring).seed_hex == original.seed_hex
    assert original.seed_hex not in capsys.readouterr().out


def test_backup_password_must_be_confirmed(
    ik: Callable[..., None],
    passwords: list[str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ik("keygen", "--keychain")
    capsys.readouterr()
    passwords.extend([PASSWORD, PASSWORD + "!"])
    _fails(
        capsys, lambda: ik("key_backup", "--out", str(tmp_path / "b")), "do not match"
    )
    assert not (tmp_path / "b").exists()


def test_backup_refuses_a_short_password_and_an_existing_file(
    ik: Callable[..., None],
    passwords: list[str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ik("keygen", "--keychain")
    capsys.readouterr()
    passwords.extend(["short", "short"])
    _fails(
        capsys, lambda: ik("key_backup", "--out", str(tmp_path / "b")), "at least 12"
    )
    existing = tmp_path / "existing"
    existing.write_text("keep me")
    _fails(capsys, lambda: ik("key_backup", "--out", str(existing)), "already exists")
    assert existing.read_text() == "keep me"


def test_restore_with_a_wrong_password(
    ik: Callable[..., None],
    passwords: list[str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    backup = tmp_path / "b"
    backup.write_bytes(keys.export_backup(Author.generate(), PASSWORD))
    passwords.append("not the password")
    _fails(
        capsys, lambda: ik("key_restore", str(backup), "--keychain"), "Wrong password"
    )


def test_restore_into_a_dotenv_file(
    monkeypatch: pytest.MonkeyPatch,
    passwords: list[str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    author = Author.generate()
    backup = tmp_path / "b"
    backup.write_bytes(keys.export_backup(author, PASSWORD))
    dotenv = tmp_path / "keys.env"
    monkeypatch.delenv("IK_AUTHOR_PRIVATE_KEY", raising=False)
    monkeypatch.setattr(
        "sys.argv",
        ["ik", "--dot-env", str(dotenv), "key_restore", str(backup), "--write"],
    )
    passwords.append(PASSWORD)
    ik_cli.main()
    assert f"IK_AUTHOR_PRIVATE_KEY='{author.seed_hex}'" in dotenv.read_text()
    assert stat.S_IMODE(dotenv.stat().st_mode) == 0o600
    assert author.seed_hex not in capsys.readouterr().out


def test_no_usable_keychain_is_a_clean_error(
    ik: Callable[..., None],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from keyring.backends import fail

    monkeypatch.setattr(keys, "_default_backend", fail.Keyring)
    _fails(capsys, lambda: ik("keygen", "--keychain"), "IK_AUTHOR_PRIVATE_KEY")
