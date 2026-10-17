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

Ed25519 signatures over canonical event bodies.

What is signed: the raw 32-byte SHA-256 digest of the canonical bytes of the
event *body* (see :mod:`indiek.core.canonical`).  Signatures are stored as
lowercase hex."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import nacl.encoding
import nacl.exceptions
import nacl.signing
from pydantic import BaseModel

from indiek.core.author import Author
from indiek.core.canonical import canonical_hash


def sign_body(body: Mapping[str, Any] | BaseModel, author: Author) -> str:
    """Sign the canonical digest of ``body`` and return the hex signature."""
    return author.sign(canonical_hash(body)).hex()


def verify_body(
    body: Mapping[str, Any] | BaseModel, signature_hex: str, public_key_hex: str
) -> bool:
    """Return whether ``signature_hex`` is ``public_key_hex``'s signature of ``body``.

    Malformed keys or signatures verify as ``False`` rather than raising.
    """
    try:
        verify_key = nacl.signing.VerifyKey(
            public_key_hex, encoder=nacl.encoding.HexEncoder
        )
        verify_key.verify(canonical_hash(body), bytes.fromhex(signature_hex))
    except (nacl.exceptions.BadSignatureError, ValueError, TypeError):
        return False
    return True
