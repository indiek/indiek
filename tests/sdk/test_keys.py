"""DESKTOP:KEY-ONBOARDING (SDK side): the author key store shared by ``ik`` and the app.

Owner decisions 2026-10-25: keys live in the OS keychain (``keyring``, optional extra
``indiek[keychain]``); ``IK_AUTHOR_PRIVATE_KEY`` wins over the keychain; no usable keychain →
a clear error and the environment variable as fallback, never a silent plaintext file;
backups are password-encrypted files only (Argon2id + XSalsa20-Poly1305 from PyNaCl).
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

import indiek
from indiek import Author, IndieKError
from indiek import keys
from indiek.keys import (
    KEYCHAIN_ACCOUNT,
    KEYCHAIN_SERVICE,
    KeychainError,
    KeychainUnavailableError,
    KeySource,
)

PASSWORD = "correct horse battery"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch: pytest.MonkeyPatch) -> None:
    """Interactive Argon2id parameters: same code path, milliseconds instead of a second."""
    from nacl import pwhash

    monkeypatch.setattr(keys, "BACKUP_OPSLIMIT", pwhash.argon2id.OPSLIMIT_MIN)
    monkeypatch.setattr(keys, "BACKUP_MEMLIMIT", pwhash.argon2id.MEMLIMIT_MIN)


class BrokenKeyring:
    """A backend that exists but cannot be used (locked, no Secret Service…)."""

    priority = 1

    def get_password(self, service: str, username: str) -> str | None:
        import keyring.errors

        raise keyring.errors.KeyringLocked("locked")

    set_password = delete_password = get_password  # type: ignore[assignment]


# -- errors and exports ---------------------------------------------------------


def test_errors_are_exported_indiek_errors() -> None:
    assert issubclass(KeychainError, IndieKError)
    assert issubclass(KeychainUnavailableError, KeychainError)
    assert indiek.KeychainError is KeychainError
    assert indiek.KeychainUnavailableError is KeychainUnavailableError


# -- keychain ---------------------------------------------------------------------


def test_store_load_delete(memory_keyring: Any) -> None:
    author = Author.generate()
    assert keys.load_from_keychain() is None
    keys.store_in_keychain(author)
    assert memory_keyring.store == {
        (KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT): author.seed_hex
    }
    loaded = keys.load_from_keychain()
    assert loaded is not None and loaded.public_key_hex == author.public_key_hex
    assert keys.delete_from_keychain() is True
    assert keys.delete_from_keychain() is False
    assert keys.load_from_keychain() is None


def test_store_refuses_to_replace_a_key_without_overwrite() -> None:
    first, second = Author.generate(), Author.generate()
    keys.store_in_keychain(first)
    with pytest.raises(KeychainError, match="already holds an IndieK author key"):
        keys.store_in_keychain(second)
    assert keys.load_from_keychain().public_key_hex == first.public_key_hex  # type: ignore[union-attr]
    keys.store_in_keychain(second, overwrite=True)
    assert keys.load_from_keychain().public_key_hex == second.public_key_hex  # type: ignore[union-attr]


def test_a_corrupted_keychain_entry_is_an_error(memory_keyring: Any) -> None:
    memory_keyring.set_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, "not-hex")
    with pytest.raises(KeychainError, match="not a valid author key"):
        keys.load_from_keychain()


def test_an_unusable_keychain_raises_a_clear_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(keys, "_default_backend", BrokenKeyring)
    assert keys.keychain_available() is False
    with pytest.raises(KeychainUnavailableError, match="IK_AUTHOR_PRIVATE_KEY"):
        keys.load_from_keychain()
    with pytest.raises(KeychainUnavailableError):
        keys.store_in_keychain(Author.generate())


def test_the_fail_backend_counts_as_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from keyring.backends import fail

    monkeypatch.setattr(keys, "_default_backend", fail.Keyring)
    assert keys.keychain_available() is False
    with pytest.raises(KeychainUnavailableError):
        keys.load_from_keychain()


def test_a_missing_keyring_package_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_package() -> object:
        raise ModuleNotFoundError("No module named 'keyring'", name="keyring")

    monkeypatch.setattr(keys, "_default_backend", no_package)
    with pytest.raises(KeychainUnavailableError, match=r"indiek\[keychain\]"):
        keys.load_from_keychain()


# -- precedence -------------------------------------------------------------------


def test_env_wins_over_the_keychain() -> None:
    stored, env = Author.generate(), Author.generate()
    keys.store_in_keychain(stored)
    resolved = keys.resolve_author({"IK_AUTHOR_PRIVATE_KEY": env.seed_hex})
    assert resolved.source is KeySource.ENV
    assert (
        resolved.author is not None
        and resolved.author.public_key_hex == env.public_key_hex
    )


def test_the_keychain_is_used_when_env_is_unset_or_blank() -> None:
    stored = Author.generate()
    keys.store_in_keychain(stored)
    for environ in ({}, {"IK_AUTHOR_PRIVATE_KEY": "  "}):
        resolved = keys.resolve_author(environ)
        assert resolved.source is KeySource.KEYCHAIN
        assert resolved.author.public_key_hex == stored.public_key_hex  # type: ignore[union-attr]


def test_no_key_anywhere_is_read_only() -> None:
    resolved = keys.resolve_author({})
    assert resolved.author is None and resolved.source is KeySource.NONE


def test_no_keychain_falls_back_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(keys, "_default_backend", BrokenKeyring)
    assert keys.resolve_author({}).source is KeySource.NONE


def test_an_invalid_env_key_is_an_error_not_a_fallback() -> None:
    keys.store_in_keychain(Author.generate())
    with pytest.raises(ValueError):
        keys.resolve_author({"IK_AUTHOR_PRIVATE_KEY": "zz"})


def test_the_default_environ_is_the_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = Author.generate()
    monkeypatch.setenv("IK_AUTHOR_PRIVATE_KEY", env.seed_hex)
    assert keys.resolve_author().source is KeySource.ENV


# -- encrypted backups ------------------------------------------------------------


def test_backup_round_trip() -> None:
    author = Author.generate()
    data = keys.export_backup(author, PASSWORD)
    restored = keys.import_backup(data, PASSWORD)
    assert restored.seed_hex == author.seed_hex


def test_backup_file_format_never_contains_the_seed() -> None:
    author = Author.generate()
    data = keys.export_backup(author, PASSWORD)
    assert author.seed_hex.encode() not in data
    doc = json.loads(data)
    assert doc["format"] == "indiek-key-backup"
    assert doc["version"] == 1
    assert doc["public_key"] == author.public_key_hex
    assert doc["kdf"]["name"] == "argon2id"
    assert doc["cipher"] == "xsalsa20-poly1305"
    assert len(base64.b64decode(doc["kdf"]["salt"])) == 16
    assert len(base64.b64decode(doc["nonce"])) == 24
    # Fresh salt and nonce every time.
    assert keys.export_backup(author, PASSWORD) != data


def test_backups_need_a_password_of_12_characters() -> None:
    with pytest.raises(ValueError, match="at least 12 characters"):
        keys.export_backup(Author.generate(), "short")


def test_a_wrong_password_is_refused() -> None:
    data = keys.export_backup(Author.generate(), PASSWORD)
    with pytest.raises(ValueError, match="Wrong password or damaged backup"):
        keys.import_backup(data, "another password!")


@pytest.mark.parametrize("field", ["ciphertext", "nonce", "public_key"])
def test_a_tampered_backup_is_refused(field: str) -> None:
    doc = json.loads(keys.export_backup(Author.generate(), PASSWORD))
    if field == "public_key":
        doc[field] = Author.generate().public_key_hex
    else:
        raw = bytearray(base64.b64decode(doc[field]))
        raw[0] ^= 1
        doc[field] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(ValueError, match="Wrong password or damaged backup"):
        keys.import_backup(json.dumps(doc).encode(), PASSWORD)


@pytest.mark.parametrize(
    "data",
    [
        b"not json",
        b"[]",
        json.dumps({"format": "something-else", "version": 1}).encode(),
    ],
)
def test_other_files_are_not_backups(data: bytes) -> None:
    with pytest.raises(ValueError, match="Not an IndieK key backup"):
        keys.import_backup(data, PASSWORD)


def test_unknown_versions_and_absurd_kdf_costs_are_refused() -> None:
    doc = json.loads(keys.export_backup(Author.generate(), PASSWORD))
    with pytest.raises(ValueError, match="version 2"):
        keys.import_backup(json.dumps({**doc, "version": 2}).encode(), PASSWORD)
    greedy = {**doc, "kdf": {**doc["kdf"], "memlimit": 64 * 1024**3}}
    with pytest.raises(ValueError, match="cost"):
        keys.import_backup(json.dumps(greedy).encode(), PASSWORD)
