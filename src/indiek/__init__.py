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

IndieK: a signed, append-only knowledge-graph archive format and its SDK.

    from indiek import Archive, Author

    author = Author.generate()            # or Author.from_seed_hex(seed_hex)
    ik = Archive.open("my-archive", author=author)
    node = ik.create_node("Gödel's incompleteness theorem")
    print(ik.index.alias_of(node), ik.head)
"""

from importlib.metadata import PackageNotFoundError, version

from indiek.core.archive import VerificationLevel
from indiek.core.author import Author
from indiek.core.errors import (
    ArchiveLockedError,
    ArchiveRuleError,
    AuthorshipError,
    IndieKError,
    IntegrityError,
    UnknownItemError,
)
from indiek.core.index import ArchiveIndex, IndexedItem, ItemKind, TranscriptionRecord
from indiek.core.models import EventType, MediaType, MetaEventType, ResourceType
from indiek.core.seals import Seal
from indiek.ops.ingest import IngestResult
from indiek.sdk import Archive, FsckReport

try:
    __version__ = version("indiek")
except PackageNotFoundError:  # running from a source tree without metadata
    __version__ = "0+unknown"

__all__ = [
    "Archive",
    "ArchiveIndex",
    "ArchiveLockedError",
    "ArchiveRuleError",
    "Author",
    "AuthorshipError",
    "EventType",
    "FsckReport",
    "IndexedItem",
    "IndieKError",
    "IngestResult",
    "IntegrityError",
    "ItemKind",
    "MediaType",
    "MetaEventType",
    "ResourceType",
    "Seal",
    "TranscriptionRecord",
    "UnknownItemError",
    "VerificationLevel",
    "__version__",
]
