"""The spec lives inside every archive (CLIPYPI:SPEC-IN-ARCHIVE, seal.md item 2 and
the tail of item 3).

Owner decisions 2026-10-17: D18 canonical bytes = RFC 8785 (JCS) restricted to
ASCII object keys and integers in [-(2^53-1), 2^53-1], enforced on write and on
read; D19 the package's ``SPEC.md`` is the normative spec; D20 ``SPEC.md`` /
``test_vectors.json`` absent from an archive -> silent, present but different
from the package copies -> one WARNING on FULL verification, never a failure;
D21 archive-root file list (no ``.ik-cache/``).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from indiek import Archive, ArchiveRuleError, Author, IntegrityError, ResourceType
from indiek.core.archive import ArchiveStore
from indiek.core.canonical import MAX_SAFE_INTEGER, canonical_bytes, parse_line
from indiek.core.index import ArchiveIndex
from indiek.core.models import (
    Edge,
    EventHeader,
    EventModel,
    LogTip,
    MediaType,
    MetaEdge,
    MetaEventHeader,
    MetaEventModel,
    MetaRepresentation,
    Node,
    SealModel,
    SupersedeEdge,
    SupersedeNode,
    Tag,
    Transcription,
)
from indiek.core.storage import EventLog
from indiek.ops.events import append_base

ALICE = Author.from_seed_hex("5c" * 32)  # public test vector, not a secret
SPEC_FILES = ("SPEC.md", "test_vectors.json")
ROOT_ENTRIES = [
    "MANIFEST.json",
    "SPEC.md",
    "test_vectors.json",
    "events/",
    "meta/events/",
    "seals/",
    "blobs/",
]
MODELS = (
    EventHeader,
    MetaEventHeader,
    Node,
    Edge,
    SupersedeNode,
    SupersedeEdge,
    Transcription,
    Tag,
    MetaRepresentation,
    MetaEdge,
    EventModel,
    MetaEventModel,
    SealModel,
    LogTip,
)
# Every IntegrityError message a reader may report: SPEC.md must document each.
ERROR_MESSAGES = [
    "Invalid log line",
    "not UTF-8",
    "lone surrogate",
    "Unsupported format version",
    "Invalid resource type 'none'",
    "Unsupported algorithm",
    "Algorithm mismatch",
    "Chain broken!",
    "Data tampered or bad author!",
    "File corrupted or missing!",
    "Meta anchor does not match base history",
    "Meta anchor goes back in base history",
    "Transcription does not match chain",
    "Seal chain broken!",
    "Seal does not match logs!",
    "Seal goes back in log history",
    "Blob set does not match seal!",
    "Expected seal not found in seal log",
    "Supersede event references unknown item",
    "Supersede event type does not match item",
    "Supersede edge events cannot change endpoints",
    "Supersede by a non-author of item",
    "Tag assignment references an unknown representation",
]


def _packaged(name: str) -> bytes:
    return files("indiek").joinpath("spec", name).read_bytes()


def _spec_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno >= logging.WARNING and "indiek version" in r.getMessage()
    ]


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path / "archive"


@pytest.fixture
def ik(root: Path) -> Archive:
    ik = Archive.open(root, author=ALICE)
    ik.create_node("a")
    ik.create_tag("t", "d", kind="node")
    return ik


# -- the packaged spec (D19) ----------------------------------------------------------


def test_the_package_ships_the_spec_and_the_vectors() -> None:
    spec = _packaged("SPEC.md").decode("utf-8")
    assert spec.startswith("# IndieK archive format")
    assert "3.0" in spec and "RFC 8785" in spec
    vectors = json.loads(_packaged("test_vectors.json"))
    assert vectors["format_version"] == "3.1"
    assert "2^53" in vectors["rules"]["integer_range"]


@pytest.mark.parametrize("message", ERROR_MESSAGES)
def test_the_spec_documents_every_error_message(message: str) -> None:
    assert message in _packaged("SPEC.md").decode("utf-8")


# -- MANIFEST.json: schemas generated from the models ---------------------------------


def _refs(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "$ref":
                yield item
            else:
                yield from _refs(item)
    elif isinstance(value, list):
        for item in value:
            yield from _refs(item)


def test_manifest_schemas_are_generated_from_the_models(ik: Archive) -> None:
    data = json.loads(ik.write_manifest().read_text(encoding="utf-8"))
    schemas = data["schemas"]
    for model in MODELS:
        assert set(schemas[model.__name__]["properties"]) == set(model.model_fields), (
            model
        )
    assert data["log_lines"] == {
        "events/": "#/schemas/EventModel",
        "meta/events/": "#/schemas/MetaEventModel",
        "seals/": "#/schemas/SealModel",
    }


def test_every_schema_reference_resolves_inside_the_manifest(ik: Archive) -> None:
    data = json.loads(ik.write_manifest().read_text(encoding="utf-8"))
    refs = set(_refs(data))
    assert refs  # the schemas do reference each other
    for ref in refs:
        assert ref.startswith("#/schemas/"), ref
        assert ref.removeprefix("#/schemas/") in data["schemas"], ref


def test_manifest_documents_the_root_levels_and_canonical_form(ik: Archive) -> None:
    data = json.loads(ik.write_manifest().read_text(encoding="utf-8"))
    assert list(data["archive_layout"]["entries"]) == ROOT_ENTRIES
    assert "ik-cache" not in json.dumps(data["archive_layout"]["entries"])
    assert set(data["verification"]["levels"]) == {"none", "incremental", "full"}
    assert "outside the archive" in data["verification"]["cache"]
    canonical = data["event_log"]["canonical_bytes"]
    assert "RFC 8785" in canonical and "2^53" in canonical
    assert data["spec"] == {"normative": "SPEC.md", "test_vectors": "test_vectors.json"}


# -- the spec files inside the archive (D20, D21) --------------------------------------


def test_write_manifest_copies_the_spec_and_the_vectors(
    ik: Archive, root: Path
) -> None:
    ik.write_manifest()
    for name in SPEC_FILES:
        assert (root / name).read_bytes() == _packaged(name), name


def test_the_archive_root_holds_only_the_documented_entries(
    ik: Archive, root: Path
) -> None:
    ik.seal()
    ik.write_manifest()
    # `.ik.lock` = the advisory write lock (SDK2:WRITE-LOCK), not archive content.
    assert {p.name for p in root.iterdir()} - {".ik.lock"} == {
        "MANIFEST.json",
        "SPEC.md",
        "test_vectors.json",
        "events",
        "meta",
        "seals",
        "blobs",
    }
    assert {p.name for p in (root / "meta").iterdir()} == {"events"}


def test_absent_spec_files_are_silent(
    ik: Archive, root: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        Archive.open(root, verify="full")
    assert _spec_warnings(caplog) == []


def test_identical_spec_files_are_silent(
    ik: Archive, root: Path, caplog: pytest.LogCaptureFixture
) -> None:
    ik.write_manifest()
    with caplog.at_level(logging.WARNING):
        Archive.open(root, verify="full")
    assert _spec_warnings(caplog) == []


@pytest.mark.parametrize("name", SPEC_FILES)
def test_a_different_spec_file_warns_on_full_verification_only(
    ik: Archive, root: Path, caplog: pytest.LogCaptureFixture, name: str
) -> None:
    ik.write_manifest()
    (root / name).write_bytes(_packaged(name) + b"\n")  # e.g. another indiek version
    with caplog.at_level(logging.WARNING):
        reopened = Archive.open(root)  # INCREMENTAL: not checked
    assert _spec_warnings(caplog) == []
    with caplog.at_level(logging.WARNING):
        full = Archive.open(root, verify="full")  # never a failure
    (message,) = _spec_warnings(caplog)
    assert name in message and "another indiek version" in message
    assert reopened.head == full.head == ik.head


# -- D18: integers in [-(2^53-1), 2^53-1] ----------------------------------------------


def test_the_canonical_integer_range() -> None:
    assert MAX_SAFE_INTEGER == 2**53 - 1


@pytest.mark.parametrize("number", [2**53, -(2**53), 10**30])
def test_out_of_range_integers_are_rejected_on_read(number: int) -> None:
    with pytest.raises(IntegrityError, match="outside"):
        parse_line(json.dumps({"a": {"b": [number]}}))


def test_in_range_extremes_are_accepted_on_read() -> None:
    edge = MAX_SAFE_INTEGER
    assert parse_line(json.dumps({"a": [edge, -edge, 0]})) == {"a": [edge, -edge, 0]}


def test_a_huge_integer_literal_is_an_integrity_error() -> None:
    with pytest.raises(IntegrityError, match="outside"):
        parse_line('{"a": ' + "9" * 5000 + "}")


@pytest.mark.parametrize("value", [2**53, -(2**53), 1.5])
def test_numbers_outside_the_canonical_form_are_refused_on_write(value: object) -> None:
    with pytest.raises(ArchiveRuleError):
        canonical_bytes({"a": {"b": [value]}})


def test_canonical_bytes_accept_booleans_and_in_range_integers() -> None:
    obj = {"t": True, "n": MAX_SAFE_INTEGER, "z": None}
    assert canonical_bytes(obj) == b'{"n":9007199254740991,"t":true,"z":null}'


def test_a_writer_cannot_append_an_out_of_range_integer(root: Path) -> None:
    body = Node(
        resource_type=ResourceType.LOCAL_FILE,
        media_type=MediaType.TEXT_PLAIN,
        path="/data/huge.txt",
        file_size=2**53,
        file_hash="sha256:" + "ab" * 32,
        last_verified=datetime(2026, 10, 18, tzinfo=UTC),
    )
    with pytest.raises(ArchiveRuleError, match="outside"):
        append_base(ArchiveIndex(ArchiveStore.open(root)), ALICE, body)
    assert not (root / "events").exists()


# -- text encoding: UTF-8 and Unicode scalar values ------------------------------------


def test_a_log_line_that_is_not_utf8_is_an_integrity_error(tmp_path: Path) -> None:
    day = tmp_path / "events" / "2026" / "10" / "18"
    day.mkdir(parents=True)
    (day / "events.ndjson").write_bytes(b'{"a": "\xff"}\n')
    with pytest.raises(IntegrityError, match="not UTF-8"):
        list(EventLog(tmp_path / "events"))


def test_bit_rot_into_invalid_utf8_fails_the_open(ik: Archive, root: Path) -> None:
    (path,) = (root / "events").rglob("*ndjson")
    raw = bytearray(path.read_bytes())
    raw[10] = 0xFF  # one byte flipped inside the first line
    path.write_bytes(bytes(raw))
    with pytest.raises(IntegrityError, match="not UTF-8"):
        Archive.open(root)


def test_a_lone_surrogate_is_an_integrity_error() -> None:
    obj = parse_line('{"a": "\\ud800"}')
    with pytest.raises(IntegrityError, match="lone surrogate"):
        canonical_bytes(obj)


def test_an_escaped_surrogate_pair_is_a_valid_character() -> None:
    obj = parse_line('{"a": "\\ud83d\\ude00"}')
    assert canonical_bytes(obj) == '{"a":"😀"}'.encode("utf-8")
