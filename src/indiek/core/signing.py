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

Ed25519 signatures over whole events (format 3.0).

What is signed: the canonical bytes (see :mod:`indiek.core.canonical`) of the
whole event *minus* its ``signature`` field, i.e. ``{"body": …, "header": …}``.
The bytes are signed directly (no pre-hash).  Signing the header binds each
signature to its chain position (``prev_hash``), time and author, so a signed
event cannot be replayed elsewhere in a chain.  Signatures are stored as
``ed25519:<lowercase hex>`` (see :func:`indiek.core.canonical.parse_signature`)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import nacl.encoding
import nacl.exceptions
import nacl.signing
from pydantic import BaseModel

from indiek.core.author import Author
from indiek.core.canonical import (
    DEFAULT_SIG_ALG,
    canonical_bytes,
    json_ready,
    parse_signature,
)
from indiek.core.errors import IntegrityError


def signing_bytes(
    obj: Mapping[str, Any] | BaseModel, signature_field: str = "signature"
) -> bytes:
    """The bytes a signature covers: ``obj`` without its signature field."""
    unsigned = json_ready(obj)
    unsigned.pop(signature_field, None)
    return canonical_bytes(unsigned)


def sign_object(
    obj: Mapping[str, Any] | BaseModel, author: Author, signature_field: str
) -> str:
    """Sign ``obj`` minus ``signature_field``; return ``ed25519:<hex>``."""
    return f"{DEFAULT_SIG_ALG}:{author.sign(signing_bytes(obj, signature_field)).hex()}"


def verify_object(
    obj: Mapping[str, Any], public_key_hex: object, signature_field: str
) -> bool:
    """Whether ``obj[signature_field]`` is ``public_key_hex``'s signature of
    ``obj`` minus that field.  Malformed input verifies as ``False``."""
    try:
        sig_alg, signature = parse_signature(obj[signature_field])
        if sig_alg != DEFAULT_SIG_ALG or not isinstance(public_key_hex, str):
            return False
        verify_key = nacl.signing.VerifyKey(
            public_key_hex, encoder=nacl.encoding.HexEncoder
        )
        verify_key.verify(signing_bytes(obj, signature_field), signature)
    except (
        nacl.exceptions.BadSignatureError,
        IntegrityError,
        ValueError,
        TypeError,
        KeyError,
    ):
        return False
    return True


def sign_event(event: Mapping[str, Any] | BaseModel, author: Author) -> str:
    """Sign ``event`` (any ``signature`` field is ignored).

    Returns the prefixed signature ``ed25519:<hex>``.
    """
    return sign_object(event, author, "signature")


def verify_event(event: Mapping[str, Any]) -> bool:
    """Whether ``event["signature"]`` is ``header.author``'s signature of ``event``.

    Malformed keys, signatures or events verify as ``False`` rather than raising.
    """
    header = event.get("header")
    author = header.get("author") if isinstance(header, Mapping) else None
    return verify_object(event, author, "signature")
