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


def signing_bytes(event: Mapping[str, Any] | BaseModel) -> bytes:
    """The bytes an event's signature covers: the event without ``signature``."""
    unsigned = json_ready(event)
    unsigned.pop("signature", None)
    return canonical_bytes(unsigned)


def sign_event(event: Mapping[str, Any] | BaseModel, author: Author) -> str:
    """Sign ``event`` (any ``signature`` field is ignored).

    Returns the prefixed signature ``ed25519:<hex>``.
    """
    return f"{DEFAULT_SIG_ALG}:{author.sign(signing_bytes(event)).hex()}"


def verify_event(event: Mapping[str, Any]) -> bool:
    """Whether ``event["signature"]`` is ``header.author``'s signature of ``event``.

    Malformed keys, signatures or events verify as ``False`` rather than raising.
    """
    try:
        sig_alg, signature = parse_signature(event["signature"])
        if sig_alg != DEFAULT_SIG_ALG:
            return False
        verify_key = nacl.signing.VerifyKey(
            event["header"]["author"], encoder=nacl.encoding.HexEncoder
        )
        verify_key.verify(signing_bytes(event), signature)
    except (
        nacl.exceptions.BadSignatureError,
        IntegrityError,
        ValueError,
        TypeError,
        KeyError,
    ):
        return False
    return True
