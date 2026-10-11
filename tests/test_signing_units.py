"""Unit tests for ``indiek.signing`` (no CLI involved)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import nacl.signing
import pytest
from pydantic import BaseModel

from indiek.signing import (
    get_canonical_hash,
    get_signing_key,
    sign_event,
    verify_signature,
)

BODY: dict[str, Any] = {"b": [1, 2], "a": "text", "c": {"y": None, "x": True}}


class _Sample(BaseModel):
    name: str
    count: int


def test_get_signing_key_accepts_32_byte_seed(author_seed_hex: str) -> None:
    assert isinstance(get_signing_key(author_seed_hex), nacl.signing.SigningKey)


@pytest.mark.parametrize("n_bytes", [16, 33])
def test_get_signing_key_rejects_wrong_length(n_bytes: int) -> None:
    with pytest.raises(ValueError, match="Invalid key length"):
        get_signing_key("ab" * n_bytes)


def test_canonical_hash_is_key_order_independent() -> None:
    reordered = {"c": {"x": True, "y": None}, "a": "text", "b": [1, 2]}
    assert get_canonical_hash(BODY) == get_canonical_hash(reordered)


def test_canonical_hash_uses_default_separators() -> None:
    default = hashlib.sha256(json.dumps(BODY, sort_keys=True).encode("utf-8")).digest()
    compact = hashlib.sha256(
        json.dumps(BODY, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).digest()

    assert get_canonical_hash(BODY) == default
    assert get_canonical_hash(BODY) != compact


def test_canonical_hash_of_model_matches_its_json_dump() -> None:
    model = _Sample(name="n", count=3)
    assert get_canonical_hash(model) == get_canonical_hash(
        model.model_dump(mode="json")
    )


def test_sign_then_verify_round_trip(
    author_seed_hex: str, author_public_key: str
) -> None:
    signature = sign_event(BODY, get_signing_key(author_seed_hex))

    assert len(signature) == 128
    assert signature == signature.lower()
    assert verify_signature(BODY, signature, author_public_key)


def test_verify_rejects_wrong_public_key(
    author_seed_hex: str, other_author: tuple[str, str]
) -> None:
    signature = sign_event(BODY, get_signing_key(author_seed_hex))
    assert not verify_signature(BODY, signature, other_author[1])


def test_verify_rejects_mutated_body(
    author_seed_hex: str, author_public_key: str
) -> None:
    signature = sign_event(BODY, get_signing_key(author_seed_hex))
    assert not verify_signature({**BODY, "a": "changed"}, signature, author_public_key)


def test_verify_rejects_malformed_signature(author_public_key: str) -> None:
    assert not verify_signature(BODY, "zz", author_public_key)
