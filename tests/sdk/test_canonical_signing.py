"""Unit tests for ``indiek.core.canonical`` and ``indiek.core.signing``.

The reference implementation of format 2.0 is spelled out inline (stdlib +
PyNaCl only) so these tests keep pinning the rule after the legacy
``indiek.signing`` module is deleted.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from pydantic import BaseModel

from indiek.core.author import Author
from indiek.core.canonical import canonical_bytes, canonical_hash
from indiek.core.signing import sign_body, verify_body

BODY: dict[str, Any] = {"b": [1, 2], "a": "Gödel", "c": {"y": None, "x": True}}
SEED_HEX = "22" * 32  # public test vector, not a secret


class _Sample(BaseModel):
    name: str
    count: int


def _reference_bytes(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True).encode("utf-8")


def test_canonical_bytes_follow_the_2_0_rule() -> None:
    assert canonical_bytes(BODY) == _reference_bytes(BODY)
    # default separators and ASCII escaping, not compact JSON
    assert b'"a": "G\\u00f6del"' in canonical_bytes(BODY)


def test_canonical_bytes_are_key_order_independent() -> None:
    reordered = {"c": {"x": True, "y": None}, "a": "Gödel", "b": [1, 2]}
    assert canonical_bytes(BODY) == canonical_bytes(reordered)


def test_model_and_its_json_dump_are_canonically_equal() -> None:
    model = _Sample(name="n", count=3)
    assert canonical_bytes(model) == canonical_bytes(model.model_dump(mode="json"))


def test_canonical_hash_is_sha256_of_canonical_bytes() -> None:
    assert canonical_hash(BODY) == hashlib.sha256(_reference_bytes(BODY)).digest()
    assert len(canonical_hash(BODY)) == 32


def test_sign_body_matches_reference_signature() -> None:
    author = Author.from_seed_hex(SEED_HEX)
    digest = hashlib.sha256(_reference_bytes(BODY)).digest()
    expected = author.signing_key.sign(digest).signature.hex()
    assert sign_body(BODY, author) == expected


def test_sign_then_verify_round_trip() -> None:
    author = Author.from_seed_hex(SEED_HEX)
    signature = sign_body(BODY, author)
    assert len(signature) == 128 and signature == signature.lower()
    assert verify_body(BODY, signature, author.public_key_hex)


def test_verify_rejects_wrong_key() -> None:
    signature = sign_body(BODY, Author.from_seed_hex(SEED_HEX))
    assert not verify_body(BODY, signature, Author.generate().public_key_hex)


def test_verify_rejects_mutated_body() -> None:
    author = Author.from_seed_hex(SEED_HEX)
    signature = sign_body(BODY, author)
    assert not verify_body({**BODY, "a": "changed"}, signature, author.public_key_hex)


@pytest.mark.parametrize("signature", ["zz", "", "00" * 64])
def test_verify_rejects_malformed_or_wrong_signature(signature: str) -> None:
    author = Author.from_seed_hex(SEED_HEX)
    assert not verify_body(BODY, signature, author.public_key_hex)


def test_verify_rejects_malformed_public_key() -> None:
    signature = sign_body(BODY, Author.from_seed_hex(SEED_HEX))
    assert not verify_body(BODY, signature, "not-hex")
