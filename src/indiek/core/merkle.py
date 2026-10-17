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

Merkle root of the blob store (``blob_root`` in seals).

The root is the RFC 6962 (Certificate Transparency) Merkle Tree Hash over the
blob digests sorted in ascending hex order, each leaf being the raw 32-byte
digest::

    leaf     = SHA-256(0x00 || digest_bytes)
    internal = SHA-256(0x01 || left || right)
    empty    = SHA-256("")

Nodes are paired level by level, an odd last node being promoted unchanged;
this yields exactly RFC 6962's root.  The 0x00/0x01 prefixes keep leaves and
inner nodes from being confused.  The root covers missing AND extra blobs."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from indiek.core.errors import IntegrityError

_DIGEST = re.compile(r"(?:sha256:)?([0-9a-f]{64})")


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def blob_root(digests: Iterable[str]) -> str:
    """``sha256:<hex>`` Merkle root of SHA-256 blob digests (bare or prefixed).

    Raises:
        IntegrityError: ``"Invalid blob name …"`` for anything that is not a
            lowercase hex SHA-256 digest (e.g. a stray file in the store).
    """
    hexes: list[str] = []
    for value in digests:
        match = _DIGEST.fullmatch(value)
        if match is None:
            raise IntegrityError(f"Invalid blob name {value!r} in the blob store")
        hexes.append(match.group(1))
    level = [_sha256(b"\x00" + bytes.fromhex(h)) for h in sorted(hexes)]
    if not level:
        return "sha256:" + _sha256(b"").hex()
    while len(level) > 1:
        paired = [
            _sha256(b"\x01" + level[i] + level[i + 1])
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2:
            paired.append(level[-1])
        level = paired
    return "sha256:" + level[0].hex()
