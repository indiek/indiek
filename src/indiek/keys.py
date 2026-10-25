"""Copyright 2026 Adrian Ernesto Radillo

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

The author key store shared by ``ik`` and the IndieK Desktop App.

Owner decisions 2026-10-25 (DESKTOP:KEY-ONBOARDING):

* The key lives in the OS keychain (macOS Keychain, Windows Credential
  Manager, Linux Secret Service) through the ``keyring`` package, installed by
  the ``indiek[keychain]`` and ``indiek[cli]`` extras.  One identity per OS user.
* ``IK_AUTHOR_PRIVATE_KEY`` (environment or dotenv file) wins over the keychain.
* Without a usable keychain: :class:`KeychainUnavailableError`, and the
  environment variable remains the way to sign; the seed is never written to
  a plaintext file behind the user's back.
* Backups are password-encrypted files only: Argon2id key derivation and
  XSalsa20-Poly1305 authenticated encryption (both from PyNaCl).
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from nacl import pwhash, secret, utils
from nacl.exceptions import CryptoError

from indiek.core.author import Author
from indiek.core.errors import KeychainError, KeychainUnavailableError

ENV_VAR = "IK_AUTHOR_PRIVATE_KEY"
KEYCHAIN_SERVICE = "indiek"
KEYCHAIN_ACCOUNT = "author-seed"

BACKUP_FORMAT = "indiek-key-backup"
BACKUP_VERSION = 1
MIN_BACKUP_PASSWORD_LENGTH = 12
# Read at call time (tests lower them); 256 MiB and ≈ 4 s per backup or restore on the
# owner's macOS arm64 machine (2026-10-25; see SDK2:PERF-ED25519 on this libsodium build).
BACKUP_OPSLIMIT = pwhash.argon2id.OPSLIMIT_MODERATE
BACKUP_MEMLIMIT = pwhash.argon2id.MEMLIMIT_MODERATE
_DAMAGED = "Wrong password or damaged backup"


class KeySource(StrEnum):
    """Where the signing key came from."""

    ENV = "env"
    KEYCHAIN = "keychain"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class ResolvedAuthor:
    """Result of :func:`resolve_author`; ``author`` is ``None`` for read-only use."""

    author: Author | None
    source: KeySource


class _Backend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...
    def set_password(self, service: str, username: str, password: str) -> None: ...
    def delete_password(self, service: str, username: str) -> None: ...


def _default_backend() -> _Backend:
    import keyring

    return keyring.get_keyring()


def _backend() -> _Backend:
    try:
        backend = _default_backend()
    except ModuleNotFoundError as exc:
        raise KeychainUnavailableError(
            "OS keychain support is not installed (pip install 'indiek[keychain]'); "
            f"set {ENV_VAR} instead"
        ) from exc
    if getattr(backend, "priority", 1) <= 0:  # keyring's "fail"/null backends
        raise KeychainUnavailableError(
            f"No usable OS keychain on this system; set {ENV_VAR} instead"
        )
    return backend


def _keychain_call[T](action: str, call: Any) -> T:
    from keyring.errors import KeyringError

    try:
        return call()
    except KeyringError as exc:
        raise KeychainUnavailableError(
            f"The OS keychain refused to {action} the IndieK author key ({exc}); "
            f"set {ENV_VAR} instead"
        ) from exc


def keychain_available() -> bool:
    """Whether an OS keychain can be read right now."""
    try:
        backend = _backend()
        _keychain_call(
            "read", lambda: backend.get_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        )
    except KeychainUnavailableError:
        return False
    return True


def load_from_keychain() -> Author | None:
    """The author stored in the OS keychain, or ``None`` if there is none.

    Raises:
        KeychainUnavailableError: no usable keychain.
        KeychainError: the stored entry is not a valid key.
    """
    backend = _backend()
    seed: str | None = _keychain_call(
        "read", lambda: backend.get_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
    )
    if seed is None:
        return None
    try:
        return Author.from_seed_hex(seed)
    except ValueError:
        raise KeychainError(
            f"The keychain entry {KEYCHAIN_SERVICE}/{KEYCHAIN_ACCOUNT} is not a valid "
            "author key"
        ) from None


def store_in_keychain(author: Author, *, overwrite: bool = False) -> None:
    """Store ``author`` in the OS keychain.

    Raises:
        KeychainError: a key is already stored and ``overwrite`` is false.
        KeychainUnavailableError: no usable keychain.
    """
    backend = _backend()
    existing = _keychain_call(
        "read", lambda: backend.get_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
    )
    if existing is not None and not overwrite:
        raise KeychainError(
            "The OS keychain already holds an IndieK author key; replacing it loses "
            "that identity unless it is backed up (overwrite explicitly)"
        )
    _keychain_call(
        "store",
        lambda: backend.set_password(
            KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, author.seed_hex
        ),
    )


def delete_from_keychain() -> bool:
    """Remove the stored key; ``False`` if there was none."""
    from keyring.errors import PasswordDeleteError

    backend = _backend()
    try:
        _keychain_call(
            "delete",
            lambda: backend.delete_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT),
        )
    except KeychainUnavailableError as exc:
        if isinstance(exc.__cause__, PasswordDeleteError):
            return False
        raise
    return True


def resolve_author(environ: Mapping[str, str] | None = None) -> ResolvedAuthor:
    """The signing author: ``IK_AUTHOR_PRIVATE_KEY`` first, then the OS keychain.

    No key anywhere, or no usable keychain, gives ``KeySource.NONE`` (read-only).

    Raises:
        ValueError: ``IK_AUTHOR_PRIVATE_KEY`` is set but malformed (no fallback).
        KeychainError: the keychain entry is not a valid key.
    """
    env = os.environ if environ is None else environ
    seed = env.get(ENV_VAR, "").strip()
    if seed:
        return ResolvedAuthor(Author.from_seed_hex(seed), KeySource.ENV)
    try:
        stored = load_from_keychain()
    except KeychainUnavailableError:
        return ResolvedAuthor(None, KeySource.NONE)
    if stored is None:
        return ResolvedAuthor(None, KeySource.NONE)
    return ResolvedAuthor(stored, KeySource.KEYCHAIN)


# -- encrypted backups -------------------------------------------------------------


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def export_backup(author: Author, password: str) -> bytes:
    """A password-encrypted backup of ``author`` (UTF-8 JSON, safe to store anywhere).

    Raises:
        ValueError: ``password`` is shorter than 12 characters.
    """
    if len(password) < MIN_BACKUP_PASSWORD_LENGTH:
        raise ValueError(
            f"The backup password must have at least {MIN_BACKUP_PASSWORD_LENGTH} characters"
        )
    salt = utils.random(pwhash.argon2id.SALTBYTES)
    key = pwhash.argon2id.kdf(
        secret.SecretBox.KEY_SIZE,
        password.encode("utf-8"),
        salt,
        opslimit=BACKUP_OPSLIMIT,
        memlimit=BACKUP_MEMLIMIT,
    )
    nonce = utils.random(secret.SecretBox.NONCE_SIZE)
    ciphertext = (
        secret.SecretBox(key).encrypt(bytes.fromhex(author.seed_hex), nonce).ciphertext
    )
    document = {
        "format": BACKUP_FORMAT,
        "version": BACKUP_VERSION,
        "public_key": author.public_key_hex,
        "kdf": {
            "name": "argon2id",
            "opslimit": BACKUP_OPSLIMIT,
            "memlimit": BACKUP_MEMLIMIT,
            "salt": _b64(salt),
        },
        "cipher": "xsalsa20-poly1305",
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
    }
    return (json.dumps(document, indent=2) + "\n").encode("utf-8")


def import_backup(data: bytes, password: str) -> Author:
    """Decrypt a backup written by :func:`export_backup`.

    Raises:
        ValueError: not a backup, unsupported version or cost, wrong password,
            or a damaged/tampered file.
    """
    try:
        document = json.loads(data)
    except UnicodeDecodeError, json.JSONDecodeError:
        document = None
    if not isinstance(document, dict) or document.get("format") != BACKUP_FORMAT:
        raise ValueError("Not an IndieK key backup")
    if document.get("version") != BACKUP_VERSION:
        raise ValueError(
            f"Unsupported key backup version {document.get('version')} "
            f"(this indiek reads version {BACKUP_VERSION})"
        )
    try:
        kdf = document["kdf"]
        opslimit, memlimit = int(kdf["opslimit"]), int(kdf["memlimit"])
        salt = base64.b64decode(kdf["salt"], validate=True)
        nonce = base64.b64decode(document["nonce"], validate=True)
        ciphertext = base64.b64decode(document["ciphertext"], validate=True)
        public_key = str(document["public_key"])
    except KeyError, TypeError, ValueError, binascii.Error:
        raise ValueError(_DAMAGED) from None
    if kdf.get("name") != "argon2id" or document.get("cipher") != "xsalsa20-poly1305":
        raise ValueError(_DAMAGED)
    if not (
        pwhash.argon2id.OPSLIMIT_MIN <= opslimit <= pwhash.argon2id.OPSLIMIT_SENSITIVE
        and pwhash.argon2id.MEMLIMIT_MIN
        <= memlimit
        <= pwhash.argon2id.MEMLIMIT_SENSITIVE
    ):
        raise ValueError("Unsupported key derivation cost in this backup")
    if (
        len(salt) != pwhash.argon2id.SALTBYTES
        or len(nonce) != secret.SecretBox.NONCE_SIZE
    ):
        raise ValueError(_DAMAGED)
    key = pwhash.argon2id.kdf(
        secret.SecretBox.KEY_SIZE,
        password.encode("utf-8"),
        salt,
        opslimit=opslimit,
        memlimit=memlimit,
    )
    try:
        seed = secret.SecretBox(key).decrypt(ciphertext, nonce)
        author = Author.from_seed_hex(seed.hex())
    except CryptoError, ValueError:
        raise ValueError(_DAMAGED) from None
    if author.public_key_hex != public_key:
        raise ValueError(_DAMAGED)
    return author
