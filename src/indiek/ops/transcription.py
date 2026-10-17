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

Transcription events: signed re-attestations of a log's history.

A transcription says "I verified this log up to head H (its first N events)
under algorithms A on date D".  Signed under the current algorithms, it lets
a chain of custody outlive the algorithms it started with.  It attests only
the log it is appended to (the base log never commits to the meta log)."""

from __future__ import annotations

from indiek.core.author import Author
from indiek.core.canonical import algorithm_of, event_hash
from indiek.core.errors import ArchiveRuleError
from indiek.core.index import ArchiveIndex, Network
from indiek.core.models import Transcription
from indiek.ops.events import append_base, append_meta


def transcribe(
    index: ArchiveIndex,
    author: Author,
    network: Network = "base",
    note: str | None = None,
) -> str:
    """Append a transcription of the verified ``network`` log to that same log.

    ``index`` must come from a verified archive: its head and count are what
    is attested.  Returns the prefixed hash of the new transcription event.

    Raises:
        ValueError: ``network`` is neither ``"base"`` nor ``"meta"``.
        ArchiveRuleError: ``"Nothing to transcribe: the <network> log is empty"``.
    """
    store = index.store
    if network == "base":
        state, append = store.base, append_base
    elif network == "meta":
        state, append = store.meta, append_meta
    else:
        raise ValueError(f"network must be 'base' or 'meta', not {network!r}")
    if state.head is None or state.sig_alg is None:
        raise ArchiveRuleError(f"Nothing to transcribe: the {network} log is empty")
    body = Transcription(
        verified_head=state.head,
        verified_count=state.count,
        verified_hash_alg=algorithm_of(state.head),
        verified_sig_alg=state.sig_alg,
        note=note,
    )
    event = append(index, author, body)  # type: ignore[arg-type]
    return event_hash(event, event.header.hash_alg)
