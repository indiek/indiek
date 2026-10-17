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

The identity that signs events: an Ed25519 key pair."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Self

import nacl.encoding
import nacl.signing

SEED_BYTES = 32


@dataclass(frozen=True, slots=True)
class Author:
    """An Ed25519 signing identity.

    ``public_key_hex`` is the value written to ``header.author``.  The seed
    is the only secret; keep it out of logs and archives.
    """

    signing_key: nacl.signing.SigningKey

    @classmethod
    def from_seed_hex(cls, seed_hex: str) -> Self:
        """Load an author from a 32-byte seed encoded as 64 hex characters."""
        seed = bytes.fromhex(seed_hex)
        if len(seed) != SEED_BYTES:
            raise ValueError(
                "Invalid key length. Ed25519 private key must be 32 bytes."
            )
        return cls(nacl.signing.SigningKey(seed))

    @classmethod
    def generate(cls) -> Self:
        """Create a fresh random author."""
        return cls(nacl.signing.SigningKey.generate())

    @property
    def public_key_hex(self) -> str:
        """Lowercase hex Ed25519 public key."""
        return self.signing_key.verify_key.encode(nacl.encoding.HexEncoder).decode(
            "ascii"
        )

    @property
    def seed_hex(self) -> str:
        """Lowercase hex seed (secret)."""
        return self.signing_key.encode(nacl.encoding.HexEncoder).decode("ascii")

    def sign(self, message: bytes) -> bytes:
        """Return the detached 64-byte Ed25519 signature of ``message``."""
        return self.signing_key.sign(message).signature

    def __repr__(self) -> str:
        return f"Author(public_key_hex={self.public_key_hex!r})"
