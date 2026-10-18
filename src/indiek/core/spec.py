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

The format specification shipped inside the package and inside archives.

``indiek/spec/SPEC.md`` is the normative, human-readable specification of the
archive format (owner decision D19) and ``indiek/spec/test_vectors.json`` its
test vectors.  ``ik manifest`` copies both to the archive root, so that an
archive documents itself.  They are informative inside an archive: their
presence, absence or content never changes whether the archive is valid
(owner decision D20).  Neither file names a package version, so they only
change when the format or its wording does."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

SPEC_FILES: tuple[str, ...] = ("SPEC.md", "test_vectors.json")


def packaged_spec_file(name: str) -> bytes:
    """Bytes of a spec file as shipped in this ``indiek`` package."""
    if name not in SPEC_FILES:
        raise ValueError(f"Not a spec file: {name!r}")
    return files("indiek").joinpath("spec", name).read_bytes()


def differing_spec_files(archive_root: Path) -> list[str]:
    """Spec files present at ``archive_root`` whose bytes differ from the
    package copies (absent files are not listed)."""
    return [
        name
        for name in SPEC_FILES
        if (archive_root / name).is_file()
        and (archive_root / name).read_bytes() != packaged_spec_file(name)
    ]
