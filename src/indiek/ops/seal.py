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

Seal the archive: append a signed checkpoint of both logs and of the blobs
they reference to ``seals/seals.ndjson``.

Any key may seal.  Refused (``ArchiveRuleError``) for an empty archive, an
archive unchanged since the latest seal (owner decision D11), and while the
blob store holds files that no event references (option C, 2026-10-17):
delete those first; they are listed in the error."""

from __future__ import annotations

import logging
from indiek.core.author import Author
from indiek.core.canonical import canonical_bytes, digest
from indiek.core.errors import ArchiveRuleError
from indiek.core.index import ArchiveIndex
from indiek.core.merkle import blob_root
from indiek.core.models import LogTip, SealModel
from indiek.core.seals import Seal
from indiek.core.signing import sign_object

logger = logging.getLogger(__name__)


def seal(index: ArchiveIndex, author: Author) -> Seal:
    """Append a seal of the verified state of ``index``; return it.

    Raises:
        ArchiveRuleError: ``"Nothing to seal: the archive is empty"``,
            ``"Nothing to seal: the archive is unchanged since seal <n>"`` or
            ``"Cannot seal: <n> unreferenced blob(s) …"`` (with their paths).
    """
    store = index.store
    if store.base.count == 0 and store.meta.count == 0:
        raise ArchiveRuleError("Nothing to seal: the archive is empty")
    stray = store.unreferenced_blobs
    if stray:
        paths = ", ".join(str(store.blobs.path_for(name)) for name in stray)
        raise ArchiveRuleError(
            f"Cannot seal: {len(stray)} unreferenced blob(s) (no event uses them; "
            f"a leftover of an interrupted write, or added by hand). Delete them "
            f"and seal again: {paths}"
        )
    model = SealModel(
        seq=store.seals.count + 1,
        prev_seal_hash=store.seals.head,
        base=LogTip(head=store.base.head, count=store.base.count),
        meta=LogTip(head=store.meta.head, count=store.meta.count),
        blob_root=blob_root(store.referenced_blobs),
        key=author.public_key_hex,
    )
    candidate = Seal.from_model(model, seal_hash="")
    latest = store.seals.latest
    if latest is not None and candidate.same_state(latest):
        raise ArchiveRuleError(
            f"Nothing to seal: the archive is unchanged since seal {latest.seq}"
        )
    model.sig = sign_object(model, author, "sig")
    store.seal_log.append(model)
    return Seal.from_model(model, digest(canonical_bytes(model), model.hash_alg))
