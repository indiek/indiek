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

Verification of the seal log and the typed :class:`Seal` record.

A seal is valid when it chains onto the previous seal (``seq`` = position,
``prev_seal_hash`` = hash of the previous seal, ``null`` only for the first),
is signed by its ``key``, and names, for the base and the meta log, a tip
that exists in the verified log.  Tip counts never decrease along the seal
log.  Every seal's ``blob_root`` must equal the Merkle root of the blobs
referenced by the events it covers (owner decision 2026-10-17, option C):
an exact check of every seal that a crash leftover in ``blobs/`` can never
break.  Unreferenced files are reported by :class:`ArchiveStore` as a
WARNING.  Empty or repeated seals are valid but logged as WARNINGs (refused
on write)."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from indiek.core.canonical import (
    HASH_ALGORITHMS,
    SIGNATURE_ALGORITHMS,
    algorithm_of,
    canonical_bytes,
    digest,
)
from indiek.core.errors import IntegrityError
from indiek.core.merkle import blob_root
from indiek.core.models import EVENT_FORMAT_VERSION, LogTip, SealModel
from indiek.core.signing import verify_object
from indiek.core.storage import SealLog

if TYPE_CHECKING:
    from indiek.core.archive import ChainState

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Seal:
    """A verified seal.  ``hash`` is the one string committing to the archive."""

    hash: str
    seq: int
    prev_seal_hash: str | None
    base_head: str | None
    base_count: int
    meta_head: str | None
    meta_count: int
    blob_root: str
    time: datetime
    key: str

    @classmethod
    def from_model(cls, model: SealModel, seal_hash: str) -> Seal:
        return cls(
            hash=seal_hash,
            seq=model.seq,
            prev_seal_hash=model.prev_seal_hash,
            base_head=model.base.head,
            base_count=model.base.count,
            meta_head=model.meta.head,
            meta_count=model.meta.count,
            blob_root=model.blob_root,
            time=model.time,
            key=model.key,
        )

    def same_state(self, other: Seal) -> bool:
        """Whether both seals commit to the same tips and blob root."""
        return (
            self.base_head,
            self.base_count,
            self.meta_head,
            self.meta_count,
            self.blob_root,
        ) == (
            other.base_head,
            other.base_count,
            other.meta_head,
            other.meta_count,
            other.blob_root,
        )


@dataclass(frozen=True, slots=True)
class SealChain:
    """Every verified seal, in order."""

    seals: tuple[Seal, ...] = ()

    @property
    def head(self) -> str | None:
        return self.seals[-1].hash if self.seals else None

    @property
    def count(self) -> int:
        return len(self.seals)

    @property
    def latest(self) -> Seal | None:
        return self.seals[-1] if self.seals else None


def _check_algorithms(seal: dict[str, Any]) -> str:
    hash_alg, sig_alg = seal.get("hash_alg"), seal.get("sig_alg")
    if hash_alg not in HASH_ALGORITHMS or sig_alg not in SIGNATURE_ALGORITHMS:
        raise IntegrityError(
            f"Unsupported algorithm (hash_alg={hash_alg!r}, sig_alg={sig_alg!r})"
        )
    checks = [("sig", seal.get("sig"), sig_alg)]
    if seal.get("prev_seal_hash") is not None:
        checks.append(("prev_seal_hash", seal.get("prev_seal_hash"), hash_alg))
    for name, value, expected in checks:
        found = algorithm_of(value) if isinstance(value, str) else ""
        if found != expected:
            raise IntegrityError(
                f"Algorithm mismatch: {name} uses {found or 'no'!r} prefix, "
                f"seal says {expected!r}"
            )
    return hash_alg


def _tip_matches(tip: LogTip, hashes: Sequence[str]) -> bool:
    if tip.count > len(hashes):
        return False
    return tip.head == (hashes[tip.count - 1] if tip.count else None)


def verify_seals(seal_log: SealLog, base: ChainState, meta: ChainState) -> SealChain:
    """Verify ``seal_log`` against the verified base and meta logs.

    Raises:
        IntegrityError: ``"Unsupported format version …"``,
            ``"Unsupported algorithm …"``, ``"Algorithm mismatch …"``,
            ``"Seal chain broken!"`` (link, ``seq``, signature or shape),
            ``"Seal does not match logs!"``, ``"Seal goes back in log history"``
            or ``"Blob set does not match seal!"``.
    """
    seals: list[Seal] = []
    previous: dict[str, Any] | None = None
    covered: set[str] = set()  # grows with the (non-decreasing) seal counts
    for position, raw in enumerate(seal_log, start=1):
        if raw.get("type") != "seal":
            raise IntegrityError("Seal chain broken!")
        version = raw.get("version")
        if version != EVENT_FORMAT_VERSION:
            raise IntegrityError(f"Unsupported format version {version!r}")
        hash_alg = _check_algorithms(raw)
        expected_prev = (
            None if previous is None else digest(canonical_bytes(previous), hash_alg)
        )
        if raw.get("seq") != position or raw.get("prev_seal_hash") != expected_prev:
            raise IntegrityError("Seal chain broken!")
        if not verify_object(raw, raw.get("key"), "sig"):
            raise IntegrityError("Seal chain broken!")
        try:
            model = SealModel.model_validate(raw)
        except ValidationError:
            raise IntegrityError("Seal chain broken!") from None
        if not (
            _tip_matches(model.base, base.hashes)
            and _tip_matches(model.meta, meta.hashes)
        ):
            raise IntegrityError("Seal does not match logs!")
        seal = Seal.from_model(model, digest(canonical_bytes(raw), hash_alg))
        if seals and (
            seal.base_count < seals[-1].base_count
            or seal.meta_count < seals[-1].meta_count
        ):
            raise IntegrityError("Seal goes back in log history")
        last_base, last_meta = (
            (seals[-1].base_count, seals[-1].meta_count) if seals else (0, 0)
        )
        covered.update(b for b in base.blobs[last_base : seal.base_count] if b)
        covered.update(b for b in meta.blobs[last_meta : seal.meta_count] if b)
        if seal.blob_root != blob_root(covered):
            raise IntegrityError("Blob set does not match seal!")
        if seal.base_count == 0 and seal.meta_count == 0:
            logger.warning("Seal %d seals an empty archive", seal.seq)
        if seals and seal.same_state(seals[-1]):
            logger.warning(
                "Seal %d repeats seal %d (the archive did not change)",
                seal.seq,
                seals[-1].seq,
            )
        seals.append(seal)
        previous = raw
    return SealChain(tuple(seals))
