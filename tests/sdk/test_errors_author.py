"""Unit tests for ``indiek.core.errors`` and ``indiek.core.author``."""

from __future__ import annotations

import hashlib
import re

import nacl.encoding
import nacl.signing
import pytest

from indiek.core.author import Author
from indiek.core.errors import (
    ArchiveRuleError,
    AuthorshipError,
    IndieKError,
    IntegrityError,
    UnknownItemError,
)


@pytest.mark.parametrize(
    "error_cls", [IntegrityError, UnknownItemError, AuthorshipError, ArchiveRuleError]
)
def test_every_error_derives_from_indiek_error(error_cls: type[Exception]) -> None:
    assert issubclass(error_cls, IndieKError)


@pytest.mark.parametrize("error_cls", [UnknownItemError, AuthorshipError, ArchiveRuleError])
def test_user_facing_errors_remain_value_errors(error_cls: type[Exception]) -> None:
    """Pre-0.11 callers caught ``ValueError``; keep that contract."""
    assert issubclass(error_cls, ValueError)


def test_integrity_error_is_not_a_value_error() -> None:
    assert not issubclass(IntegrityError, ValueError)


def test_from_seed_hex_matches_pynacl(author_seed_hex: str, author_public_key: str) -> None:
    author = Author.from_seed_hex(author_seed_hex)
    assert author.public_key_hex == author_public_key
    assert isinstance(author.signing_key, nacl.signing.SigningKey)


@pytest.mark.parametrize("n_bytes", [16, 33])
def test_from_seed_hex_rejects_wrong_length(n_bytes: int) -> None:
    with pytest.raises(ValueError, match="Invalid key length"):
        Author.from_seed_hex("ab" * n_bytes)


def test_from_seed_hex_rejects_non_hex() -> None:
    with pytest.raises(ValueError):
        Author.from_seed_hex("zz" * 32)


def test_generate_gives_distinct_well_formed_keys() -> None:
    first, second = Author.generate(), Author.generate()
    assert first.public_key_hex != second.public_key_hex
    assert re.fullmatch(r"[0-9a-f]{64}", first.public_key_hex)


def test_seed_hex_round_trips() -> None:
    author = Author.generate()
    assert Author.from_seed_hex(author.seed_hex).public_key_hex == author.public_key_hex


def test_sign_verifies_against_public_key() -> None:
    author = Author.generate()
    digest = hashlib.sha256(b"payload").digest()
    signature = author.sign(digest)
    assert len(signature) == 64
    verify_key = nacl.signing.VerifyKey(
        author.public_key_hex, encoder=nacl.encoding.HexEncoder
    )
    assert verify_key.verify(digest, signature) == digest
