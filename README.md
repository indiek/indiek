# IndieK — the `indiek` SDK and the `ik` CLI

**IndieK is an archival format for knowledge graphs, built to last.** An
archive is a plain folder of signed, append-only, hash-chained event logs and
content-addressed files that anyone can verify, now or in a century, with
nothing but this specification and standard cryptography.

This package is the reference implementation: a Python SDK (`import indiek`)
and a command-line tool (`ik`). Broader context, guides and examples live on
[indiek.org](https://indiek.org).

- Package version: **1.0.0** · Archive format: **3.0** · License: Apache-2.0
- Python 3.14 or newer

## Contents

- [What is an IndieK archive?](#what-is-an-indiek-archive)
- [Install](#install)
- [Quickstart](#quickstart)
- [Concepts](#concepts)
- [Python SDK reference](#python-sdk-reference)
- [`ik` CLI reference](#ik-cli-reference)
- [Integrity, seals and trust](#integrity-seals-and-trust)
- [Known limitations](#known-limitations)
- [The archive format](#the-archive-format)
- [Contributing](#contributing)
- [License](#license)

## What is an IndieK archive?

A knowledge graph of **nodes** (a statement, a note, an image, a PDF, a link)
and **directed edges** between them (which carry content too: "proves",
"cites", "contradicts"), plus **tags** on both, stored as a folder:

```text
my-archive/
├── events/2026/10/18/events.ndjson        base log: nodes and edges
├── meta/events/2026/10/18/events.ndjson   meta log: tags and tag assignments
├── blobs/sha256/71/a0/71a0b54b…           content, named by its SHA-256
├── seals/seals.ndjson                     signed checkpoints (optional)
├── MANIFEST.json                          layout + JSON Schemas (optional)
├── SPEC.md                                the format specification (optional)
└── test_vectors.json                      test vectors (optional)
```

- **Append-only.** Every change is a new line, an *event*. Nothing is edited
  in place: revising a node appends a *supersede* event and keeps the old one.
- **Signed.** Every event is signed with its author's Ed25519 key.
- **Hash-chained.** Every event commits to the previous one, so any change to
  the history is detected.
- **Content-addressed.** Contents live in `blobs/`, each file named after the
  hash of its bytes.
- **Two networks.** The *base* log is the knowledge graph; the *meta* log
  annotates it with tags. Meta commits to base, never the reverse: a base can
  be shipped alone, and anyone can annotate it with their own key.
- **Sealed.** A *seal* is a signed checkpoint of the whole archive; its hash
  is one short string you can publish so others can check their copy.
- **Self-describing.** `ik manifest` writes `SPEC.md`, `MANIFEST.json` and
  `test_vectors.json` into the archive, so it can be read without this
  software.

## Install

```bash
uv tool install 'indiek[cli]'   # the ik command (adds rich and python-dotenv)
uv add indiek                   # the SDK only, as a dependency of your project
pip install 'indiek[cli]'       # with pip
```

The SDK depends only on `pydantic` and `pynacl`. The `cli` extra adds `rich`
(tables) and `python-dotenv` (configuration files). To install from a local
copy of this folder: `uv tool install --editable '.[cli]'`.

## Quickstart

### With the SDK

```python
from indiek import Archive, Author

author = Author.generate()  # keep author.seed_hex secret: it is your signing key
ik = Archive.open("my-archive", author=author)  # the folder is created on first write

theorem = ik.create_node("Gödel's first incompleteness theorem", title="Gödel I")
statement = ik.create_node(
    "Any consistent formal system able to express arithmetic is incomplete."
)
ik.create_edge(statement, theorem, "states")

tag = ik.create_tag("theorem", "A proven statement", kind="node")
ik.set_tag(tag, theorem)

print(ik.index.alias_of(theorem))  # e1
seal = ik.seal()
print(seal.hash)  # sha256:… — the one string that commits to the whole archive
```

### With the CLI

```bash
ik keygen --write                                  # writes IK_AUTHOR_PRIVATE_KEY to .env
ik config --set-archive-path ~/archives/my-archive # writes IK_ARCHIVE_PATH to .env

ik create_node --content "Gödel's first incompleteness theorem" --title "Gödel I"  # e1
ik create_node --content "Any consistent formal system … is incomplete."           # e2
ik create_edge --source-node e2 --target-node e1 --content "states"                # e3
ik create_node_tag --name theorem --description "A proven statement"              # m1
ik set_tag --tag m1 --id e1                                                        # m2, m3
ik read --mini
ik seal          # prints: Seal 1 created: sha256:…
ik verify        # re-checks everything
```

## Concepts

**Authors and keys.** An author is an Ed25519 key pair. The 32-byte *seed*
(64 hex characters) is the only secret; never share it or put it in an
archive. The 64-hex *public key* appears as `header.author` in every event the
author signs. Without a key an archive can only be read.

**Identifiers and aliases.** Every node, edge and tag has a UUIDv7. Opening
an archive also assigns short *aliases* by replaying the logs in order:

- base network: `e1`, `e2`, … for **both** nodes and edges, in creation order;
- meta network: `m1`, `m2`, … for tags, representations **and** tag
  assignments (so `m` numbers are not a tag counter);
- supersede and transcription events allocate no alias.

Aliases are a convenience of the projection; they are never written in the
archive. Anywhere an ID is expected, a UUID, a UUID string or an alias works.

**Resource types.** A node's content is either *managed* (stored in the blob
store; the default), a *uri* (an external link, recorded but never fetched),
or a *local_file* (a pointer to a file on this machine plus its size and
SHA-256, so a later change can be detected; the file is not copied).

**Media types.** Managed and local-file content must use an archival-safe
media type: `text/plain; charset=utf-8`, `text/markdown; charset=utf-8`,
`image/tiff`, `image/png`, `image/jpeg`, `application/pdf; profile=pdfa`.
Edges always carry `text/plain` content.

**Revisions.** `supersede_node` / `supersede_edge` append new content for an
existing item, which keeps its UUID and alias. Only the item's creator may
supersede it; to disagree with someone else's node, create your own node and
an edge to theirs. Edge endpoints never change.

**Tags.** A tag is defined once (`create_tag`) for nodes or for edges, then
assigned (`set_tag`). The first assignment to an item also creates a
*representation* of it in the meta network. Only a tag's author may assign
it; anyone may define their own tags.

**Transcriptions.** A transcription is a signed attestation, appended to a
log, that says "I verified this log up to head H". Algorithms age;
generations of transcriptions under newer algorithms keep a chain of custody
alive.

**Seals.** A seal is a signed checkpoint of both logs and of the blobs they
reference. Publish its hash; anyone can then check a copy with
`ik verify --expect <hash>`.

## Python SDK reference

The public API is everything exported by `indiek` (`indiek.__all__`). The
modules under `indiek.core` and `indiek.ops` are the building blocks behind
it; they are documented in their docstrings but are not part of the stable
API.

```python
from indiek import (
    Archive, Author,                                     # entry points
    ArchiveIndex, IndexedItem, ItemKind, TranscriptionRecord,  # the projection
    Seal, FsckReport, IngestResult,                      # results
    VerificationLevel, MediaType, ResourceType, EventType, MetaEventType,
    IndieKError, IntegrityError, UnknownItemError, AuthorshipError, ArchiveRuleError,
    __version__,
)
```

### `Author`

```python
from indiek import Author

author = Author.generate()                           # a new random key
same = Author.from_seed_hex(author.seed_hex)         # load from 64 hex characters
assert same.public_key_hex == author.public_key_hex  # what events record as author
```

| Member | Description |
| --- | --- |
| `Author.generate()` | New random Ed25519 identity. |
| `Author.from_seed_hex(seed_hex)` | Load from a 32-byte seed as 64 hex characters; `ValueError` if malformed. |
| `public_key_hex` | Lowercase hex public key (64 characters). |
| `seed_hex` | Lowercase hex seed — the secret. |
| `sign(message: bytes) -> bytes` | Raw 64-byte Ed25519 signature. |

`repr(author)` shows only the public key.

### `Archive.open`

```py
Archive.open(
    path,                    # str | Path; "~" is expanded; may not exist yet
    author=None,             # Author | None; None opens read-only
    *,
    verify="incremental",    # "none" | "incremental" | "full" (or VerificationLevel)
    trusted_seal=None,       # a seal hash you obtained separately
    cache_dir=None,          # verification cache; default: IK_CACHE_DIR or the OS cache dir
) -> Archive
```

Opening reads and verifies both event logs, the blob references and the seal
log (see [Verification levels](#verification-levels-and-the-trust-model)),
then builds the in-memory index. A folder that does not exist is an empty
archive; it is created on the first write. Raises `IntegrityError` if the
archive is corrupted or tampered with, or if `trusted_seal` is not in its
seal log; `ValueError` for an unknown `verify` level.

```python
from indiek import Archive, VerificationLevel

reader = Archive.open("my-archive")                        # read-only, incremental
everything = Archive.open("my-archive", verify="full")     # checks every signature
raw = Archive.open("my-archive", verify=VerificationLevel.NONE)  # parse only, read-only
trusted = Archive.open("my-archive", trusted_seal=seal.hash)
```

### Reading

| Member | Description |
| --- | --- |
| `path` | The archive folder. |
| `author` | The `Author` used for writes, or `None`. |
| `verification` | The `VerificationLevel` the archive was opened with. |
| `head` / `meta_head` | Hash (`sha256:…`) of the last base / meta event, or `None`. |
| `index` | The `ArchiveIndex`: current state of every item. |
| `events(network="base")` | Iterate the raw events (dicts) of the `"base"` or `"meta"` log, in order. |
| `seals()` | Every verified `Seal`, oldest first. |
| `refresh(level=None)` | Re-read and re-verify from disk (e.g. after another process wrote). |

Items are looked up by alias or UUID; their `body` is the JSON body of their
latest event. Content is read from the blob store, which re-hashes every blob
it returns:

```python
from indiek import ItemKind

item = reader.index.get("e1")
print(item.kind, item.alias, item.body["title"])  # node e1 Gödel I
print(reader.index.store.blobs.get_text(item.body["blob_hash"]))

for item in reader.index.items.values():
    if item.kind is ItemKind.EDGE:
        source = reader.index.get(item.body["source_node"])
        target = reader.index.get(item.body["target_node"])
        label = reader.index.store.blobs.get_text(item.body["blob_hash"])
        print(f"{source.alias} --{label}--> {target.alias}")  # e2 --states--> e1

for event in reader.events("meta"):
    print(event["body"]["event_type"])  # create_node_tag, create_node_representation, …
```

Use `blobs.get(hash)` for binary content (bytes). Both raise
`IntegrityError("File corrupted or missing! (blob …)")` if the file is gone
or altered.

### Writing nodes and edges

Every write needs an author (`AuthorshipError: An author is required to write
to an archive`) and an archive not opened with `verify="none"`
(`ArchiveRuleError: Writes need verification: …`). Each write appends signed
events and refreshes `index`, so the new item's alias is usable immediately.

```python
from pathlib import Path
from indiek import MediaType, ResourceType

note = ik.create_node("# Proof sketch\n\nBy diagonalisation.", media_type=MediaType.TEXT_MARKDOWN)
diagram = ik.create_node(
    Path("figures/diagram.png").read_bytes(), media_type=MediaType.IMAGE_PNG, title="Diagram"
)
paper = ik.create_node(
    resource_type=ResourceType.URI,
    uri="https://arxiv.org/abs/1234.5678",
    title="Survey",
    media_type=MediaType.APPLICATION_PDF_A,  # optional hint
)
scan = ik.create_node(resource_type=ResourceType.LOCAL_FILE, path="scans/page.tiff")
proves = ik.create_edge(note, statement, "sketches a proof of")
```

`create_node(content=None, *, media_type=None, title=None, resource_type=ResourceType.MANAGED, uri=None, path=None) -> UUID`

- `managed` (default): `content` is stored in the blob store. A `str` is
  always taken literally — never read as a file path — and defaults to
  `text/plain`; `bytes` require `media_type`. Errors: `ArchiveRuleError`
  `content is required for managed nodes`, `media_type is required for bytes content`.
- `uri`: records `uri`, never fetched; `media_type` is an optional hint.
  Error: `uri is required for uri nodes`.
- `local_file`: records the absolute resolved `path`, the file size, its
  SHA-256 and the time; the media type is detected from the file name
  (`.txt`, `.md`, `.png`, `.jpg`/`.jpeg`, `.tif`/`.tiff`) and the title
  defaults to the file stem. Errors: `path is required for local_file nodes`,
  `Local file does not exist or is not a regular file: <path>`,
  `Unsupported archival media type for <path>`.

`create_edge(source, target, content) -> UUID` — a directed edge between two
existing base **nodes**, carrying `content` as `text/plain` (stored
verbatim). Endpoints are checked before anything is written:
`UnknownItemError` `Unknown ID or alias '<ref>'`,
`SOURCE NODE <uuid> NOT FOUND IN ARCHIVE`, `TARGET NODE <uuid> NOT FOUND IN ARCHIVE`
(edges and tags can never be endpoints). Self-loops are allowed.

### Revising: supersede

```python
ik.supersede_node(theorem, "Gödel's *first* incompleteness theorem (1931)")
ik.supersede_node(theorem, "Gödel's first incompleteness theorem", title="Gödel 1931")
ik.supersede_edge("e3", "states, in modern terms")
```

`supersede_node(node, content, *, title=None, media_type=MediaType.TEXT_MARKDOWN) -> UUID`
replaces a node's content with a managed blob; `title=None` keeps the current
title. `supersede_edge(edge, content) -> UUID` replaces an edge's
`text/plain` content; endpoints and title are kept. Both return the item's
UUID, which does not change. Errors: `UnknownItemError`
`Node '<ref>' does not exist in this archive`,
`ID '<ref>' does not reference a base-network node` (and the edge
equivalents); `AuthorshipError` `Only the author of Node '<ref>' may supersede it`
(checked before anything is written).

### Tags

```python
proof = ik.create_tag("proof", "A proof relation", kind="edge")
ik.set_tag(proof, proves)
print(ik.index.items[proves].tags == {proof})  # True
```

`create_tag(name, description, *, kind) -> UUID` defines a tag for
`kind="node"` or `kind="edge"` (`ArchiveRuleError` otherwise). Names are not
unique.

`set_tag(tag, target) -> UUID` assigns a tag to a base node or edge and
returns the UUID of the assignment (a meta edge). The first assignment to a
target also appends a representation of it. Errors:

| Error | Message |
| --- | --- |
| `UnknownItemError` | `Unknown ID or alias '<ref>'`; `UUID is not part of any network (neither base nor meta)` |
| `ArchiveRuleError` | `<uuid> is not a tag node`; `UUID should not be an item from the meta network` |
| `AuthorshipError` | `Only the tag's author may use this operation` |
| `ArchiveRuleError` | `A node tag should point to a node representation`; `An edge tag should point to an edge representation` |

When the kind check fails on a first assignment, the representation already
written stays in the meta log (harmless, reused later) and a WARNING says so.
Assigning the same tag twice appends a second assignment; the item's tag set
is unchanged.

### Bulk import, export and the manifest

```python
result = ik.ingest(input_folder="more")  # one managed node per folder entry
cites = result.node_ids[0]
Path("edges.csv").write_text(f"{cites},{theorem},cites\n", encoding="utf-8")
ik.ingest(edges_file="edges.csv")        # one edge per line: source,target,content

ik.export_graphml("theorems.graphml", tags=[tag])  # base network as GraphML
ik.write_manifest()                                # MANIFEST.json, SPEC.md, test_vectors.json
```

- `ingest(*, input_folder=None, edges_file=None) -> IngestResult` — every
  entry of `input_folder` (sorted, not recursive) becomes a managed node
  titled by its stem (text files as text, images as bytes); then every line
  `source,target,content` of `edges_file` becomes an edge (split on the
  first two commas; endpoints may be UUIDs or aliases). Stops at the first
  error; earlier writes are kept. See [Known limitations](#known-limitations).
- `export_graphml(output_path, tags=()) -> Path` — writes the base network as
  pretty-printed, directed GraphML (overwritten). With `tags`, keeps items
  carrying at least one of them.
- `write_manifest() -> Path` — writes `MANIFEST.json` (layout, rules, JSON
  Schemas of every log line, algorithms used, the current author's key) and
  copies `SPEC.md` and `test_vectors.json` at the archive root; returns the
  manifest path. Works without an author.

These three, like `seal()`, `verify()` and `fsck()`, run a `full`
verification first.

### Attesting: transcriptions

```python
new_head = ik.transcribe(note="re-verified before publication")
record = ik.index.transcriptions["base"][-1]
print(record.position, record.body["verified_count"], new_head == ik.head)
```

`transcribe(network="base", *, note=None) -> str` appends to the `"base"` (or
`"meta"`) log a `transcription` event recording that log's verified head,
length and algorithms, and returns the new head. Any author may transcribe.
`ArchiveRuleError: Nothing to transcribe: the <network> log is empty`.

### Seals, verification and health

```python
second = ik.seal()
assert ik.verify(expect=seal.hash) == seal   # the first seal is still in the log
assert ik.verify() == second                 # without expect: the latest seal
report = ik.fsck()
print(report.base_count, report.seal_count, report.unreferenced_blobs)
```

| Method | Description |
| --- | --- |
| `seal() -> Seal` | Fully verify, then append a seal of both logs and their blobs. Any author may seal. `ArchiveRuleError`: `Nothing to seal: the archive is empty`, `Nothing to seal: the archive is unchanged since seal <n>`, `Cannot seal: <n> unreferenced blob(s) … Delete them and seal again: <paths>`. |
| `verify(*, expect=None) -> Seal \| None` | Re-read and fully re-verify from disk. Returns the seal whose hash is `expect` (else `IntegrityError: Expected seal not found in seal log`) or, without `expect`, the latest seal (`None` if there is none). |
| `fsck() -> FsckReport` | Fully verify and report on the archive. |
| `unreferenced_blobs() -> list[Path]` | Files in the blob store that no event references (safe to delete). |
| `seals() -> list[Seal]` | Every verified seal, oldest first. |

### The index

`ArchiveIndex` (`archive.index`) is the replayed state of the archive:

| Member | Description |
| --- | --- |
| `items: dict[UUID, IndexedItem]` | Every node, edge, tag, representation and tag assignment. |
| `aliases: dict[str, UUID]` | `e{n}` / `m{n}` → UUID. |
| `resolve(ref) -> UUID` | Alias, UUID string or UUID → UUID (`UnknownItemError` for garbage; a well-formed UUID is not checked). |
| `get(ref) -> IndexedItem` | The item (`UnknownItemError` if absent). |
| `alias_of(uuid) -> str` | The item's alias. |
| `representation_of(uuid) -> UUID \| None` / `underlying_of(uuid) -> UUID` | Base item ↔ its meta representation. |
| `transcriptions: dict[str, list[TranscriptionRecord]]` | Per network, `author`, `position` (1-based) and `body`. |
| `head` / `meta_head` | As on `Archive`. |
| `store` | The verified on-disk store; `store.blobs` reads content (`get`, `get_text`). |

`IndexedItem` fields: `id`, `alias`, `kind` (an `ItemKind`), `author` (the
creator's public key), `body` (dict of the latest event body), `tags` (set of
tag UUIDs, base items only); properties `is_meta`, `is_edge`, `is_tag`.

`ItemKind`: `NODE`, `EDGE`, `NODE_TAG`, `EDGE_TAG`, `NODE_REPRESENTATION`,
`EDGE_REPRESENTATION`, `NODE_TAG_ASSIGNMENT`, `EDGE_TAG_ASSIGNMENT`.

### Result types

- `Seal`: `hash`, `seq`, `prev_seal_hash`, `base_head`, `base_count`,
  `meta_head`, `meta_count`, `blob_root`, `time`, `key`.
- `FsckReport`: `path`, `base_count`, `base_head`, `meta_count`, `meta_head`,
  `seal_count`, `latest_seal`, `transcriptions` (`{"base": n, "meta": m}`),
  `blob_files`, `referenced_blobs`, `unreferenced_blobs` (paths),
  `untagged_representations`.
- `IngestResult`: `node_ids`, `edge_ids` (UUIDs in creation order).

### Enumerations

- `VerificationLevel`: `NONE`, `INCREMENTAL`, `FULL` (values `"none"`, …).
- `ResourceType`: `MANAGED`, `URI`, `LOCAL_FILE`.
- `MediaType`: `TEXT_PLAIN`, `TEXT_MARKDOWN`, `IMAGE_TIFF`, `IMAGE_PNG`,
  `IMAGE_JPEG`, `APPLICATION_PDF_A` (values are the media type strings).
- `EventType` (base): `create_node`, `create_edge`, `supersede_node`,
  `supersede_edge`, `transcription`.
- `MetaEventType`: `create_node_tag`, `create_edge_tag`,
  `create_node_representation`, `create_edge_representation`,
  `set_node_tag`, `set_edge_tag`, `transcription`.

### Errors

```text
IndieKError
├── IntegrityError       the archive on disk is corrupted, tampered with or inconsistent
├── UnknownItemError     an ID or alias does not resolve (also a ValueError)
├── AuthorshipError      the current author may not do this (also a ValueError)
└── ArchiveRuleError     the write would break a rule of the format (also a ValueError)
```

```python
from indiek import IndieKError, UnknownItemError

try:
    ik.create_edge("e1", "e99", "dangling")
except UnknownItemError as exc:
    print(exc)  # Unknown ID or alias 'e99'
except IndieKError:
    raise
```

Every `IntegrityError` message is listed in
[Integrity verification](#integrity-verification) and in `SPEC.md`.

## `ik` CLI reference

### Invocation

```text
ik [--dot-env PATH] [--logging-level LEVEL] [--verify LEVEL] [--trust-seal HASH] <command> [flags]
```

Global flags apply to every command and must precede it.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--dot-env` | `.env` | Dotenv file to load. Real environment variables win over it. |
| `--logging-level` | `WARNING` | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`, case-insensitive. |
| `--verify` | `incremental` | `none`, `incremental` or `full`; see [Verification levels](#verification-levels-and-the-trust-model). |
| `--trust-seal` | — | A seal hash you obtained separately; the signatures it covers are not re-checked. |

Logs go to **stderr**; stdout carries only command output (IDs, tables,
reports), so it is safe to pipe.

| Command | Purpose | Prints on success |
| --- | --- | --- |
| [`keygen`](#ik-keygen) | Generate an author key | `IK_AUTHOR_PRIVATE_KEY=<seed>` (nothing with `--write`) |
| [`config`](#ik-config) | Show or set `IK_ARCHIVE_PATH` | `IK_ARCHIVE_PATH=<value>` |
| [`create_node`](#ik-create_node) | Add a node (`managed`, `uri`, `local_file`) | `Node created: <uuid>` |
| [`create_edge`](#ik-create_edge) | Add a directed edge between two nodes | `Edge created: <uuid>` |
| [`supersede_node`](#ik-supersede_node) | Replace a node's content | `Node superseded: <uuid>` |
| [`supersede_edge`](#ik-supersede_edge) | Replace an edge's content | `Edge superseded: <uuid>` |
| [`create_node_tag`](#ik-create_node_tag-and-ik-create_edge_tag) | Define a tag for nodes | nothing |
| [`create_edge_tag`](#ik-create_node_tag-and-ik-create_edge_tag) | Define a tag for edges | `Meta node created: <uuid>` |
| [`set_tag`](#ik-set_tag) | Assign a tag to a node or edge | nothing |
| [`read`](#ik-read) | Print both event logs as tables | two tables |
| [`export`](#ik-export) | Write the base network as GraphML | nothing |
| [`ingest`](#ik-ingest) | Bulk-create nodes and edges | nothing |
| [`transcribe`](#ik-transcribe) | Attest a log with a `transcription` event | `Transcription appended: <hash>` |
| [`seal`](#ik-seal) | Append a signed seal of the whole archive | `Seal <n> created: <hash>` |
| [`verify`](#ik-verify) | Fully re-verify, optionally against a known seal | counts and the latest seal |
| [`fsck`](#ik-fsck) | Fully verify and print a health report | a report |
| [`manifest`](#ik-manifest) | Write `MANIFEST.json`, `SPEC.md`, `test_vectors.json` | `MANIFEST written to: <path>` |

### Environment

| Variable | Meaning |
| --- | --- |
| `IK_ARCHIVE_PATH` | Root folder of the archive (`~` is expanded). |
| `IK_AUTHOR_PRIVATE_KEY` | The author's Ed25519 seed, 64 hex characters. |
| `IK_CACHE_DIR` | Optional. Directory of the local verification cache. |

Both main variables can live in the dotenv file (`ik keygen --write`,
`ik config --set-archive-path`).

- `keygen` and `config` need neither variable.
- `read`, `export`, `manifest`, `verify` and `fsck` need only
  `IK_ARCHIVE_PATH`; without a key the archive is opened read-only (and
  `manifest` lists no author).
- Every other command also needs the key; without it:
  `ik: error: An author is required to write to an archive`.

### Errors and exit codes

| Exit status | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | The command failed: integrity, unknown item, authorship, archive rule, invalid key. One line `ik: error: <message>` on stderr, no traceback (`--logging-level DEBUG` adds it). |
| `2` | Usage error: missing or invalid flag, or `IK_ARCHIVE_PATH` not set. |

A malformed key exits 1 with `ik: error: IK_AUTHOR_PRIVATE_KEY is invalid: <reason>`;
the key itself is never printed. The messages are those of the SDK errors
(see [Errors](#errors)).

---

### `ik keygen`

Generates a fresh Ed25519 author key. Needs neither a key nor an archive.

| Flag | Meaning |
| --- | --- |
| `--write` | Store the seed in the `--dot-env` file (mode `600`) instead of printing it. |
| `--force` | With `--write`, replace a key already in that file. The old key is lost. |

Without `--write`: prints `IK_AUTHOR_PRIVATE_KEY=<64 hex>` on stdout and
`Public key: <hex>` on stderr. With `--write`: nothing on stdout; stderr
names the file and the public key. If the file already holds a key and
`--force` is absent, exits 1 and leaves it untouched. The seed is your
signing identity: back it up privately, never share it.

```bash
ik --dot-env .env keygen --write
```

### `ik config`

Shows, and optionally sets, `IK_ARCHIVE_PATH` in the `--dot-env` file. Needs
neither a key nor an existing archive.

| Flag | Meaning |
| --- | --- |
| `--set-archive-path` | Archive path to write into the dotenv file (stored single-quoted). |

Prints `IK_ARCHIVE_PATH=<value>` or `IK_ARCHIVE_PATH is not set`; when
setting, then `IK_ARCHIVE_PATH=<new path>`.

```bash
ik config --set-archive-path ~/archives/my-archive
```

### `ik create_node`

Appends a `create_node` event.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--content` | for `managed` | Inline text, or the path of a supported file. |
| `--title` | no | Title stored in the event. |
| `--resource-type` | no | `managed` (default), `uri` or `local_file`. |
| `--uri` | for `uri` | External URL, never fetched. |
| `--path` | for `local_file` | Local file, never copied. |
| `--media-type` | no | One of the archival media types; a hint for `uri` nodes. |

- **managed**: if `--content` names an existing file, the file is read — text
  for `.txt`/`.md`, bytes for `.png`, `.jpg`, `.tif`/`.tiff` — with the media
  type detected from its name; any other file fails with
  `Unsupported archival media type for <path>` and nothing is written.
  Otherwise `--content` is stored as `text/plain`. `--media-type` is ignored
  for managed nodes. Missing `--content` exits 2.
- **uri**: records `--uri` and the optional `--media-type`. Missing `--uri`
  exits 2.
- **local_file**: records the absolute path, size, SHA-256 and time of
  `--path`; media type detected as above; title defaults to the file stem.
  Missing `--path` exits 2; a missing file fails with
  `Local file does not exist or is not a regular file: <path>`.
- If `--title` is omitted and `--content` names an existing file, the title is
  the file's stem.

```bash
ik create_node --content "Gödel's incompleteness theorem"
ik create_node --content ./notes/limits.md --title "Limits"
ik create_node --resource-type uri --uri https://arxiv.org/abs/1234.5678 \
  --title "The paper" --media-type "application/pdf; profile=pdfa"
ik create_node --resource-type local_file --path ~/scans/page.tiff
```

### `ik create_edge`

Appends a directed edge that carries text.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--source-node` | yes | Source node (UUID or alias). |
| `--target-node` | yes | Target node (UUID or alias). |
| `--content` | yes | Edge text, stored verbatim as `text/plain` (a file path is not read). |

Both endpoints must be existing base nodes, checked before anything is
written (`Unknown ID or alias '<ref>'`, `SOURCE NODE <uuid> NOT FOUND IN ARCHIVE`,
`TARGET NODE <uuid> NOT FOUND IN ARCHIVE`). Use `ik read` to see the new
`e{n}` alias.

```bash
ik create_edge --source-node e2 --target-node e1 --content "states"
```

### `ik supersede_node`

Appends replacement content for a node; history is kept.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--node-id` | yes | Node (UUID or alias). |
| `--content` | yes | Replacement content, stored as `text/markdown`. |
| `--title` | no | New title; the current one is kept when omitted. |

Only the node's creator may supersede it
(`Only the author of Node '<ref>' may supersede it`). Other errors:
`Node '<ref>' does not exist in this archive`,
`ID '<ref>' does not reference a base-network node`.

```bash
ik supersede_node --node-id e1 --content "Gödel's *first* incompleteness theorem"
```

### `ik supersede_edge`

| Flag | Required | Meaning |
| --- | --- | --- |
| `--edge-id` | yes | Edge (UUID or alias). |
| `--content` | yes | Replacement text (`text/plain`). |

Endpoints and title are kept. Same authorship rule and errors as
`supersede_node`, for edges.

```bash
ik supersede_edge --edge-id e3 --content "strictly generalises"
```

### `ik create_node_tag` and `ik create_edge_tag`

Define a tag for nodes, or for edges, in the meta log.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--name` | yes | Tag name (not unique). |
| `--description` | yes | Tag description. |

The tag takes the next `m{n}` alias. `create_edge_tag` prints
`Meta node created: <uuid>`; `create_node_tag` prints nothing.

```bash
ik create_node_tag --name theorem --description "A proven statement"
ik create_edge_tag --name proof --description "Proof relation"
```

### `ik set_tag`

Assigns a tag to a base node or edge.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--tag` | yes | Tag (UUID or `m{n}` alias). |
| `--id` | yes | Node or edge to tag (UUID or `e{n}` alias). |

The first assignment to an item writes two meta events (a representation,
then the assignment) and so consumes two `m{n}` aliases. Errors are those of
[`set_tag`](#tags) in the SDK. Prints nothing.

```bash
ik set_tag --tag m1 --id e1
```

### `ik read`

Prints two tables on stdout: **Events Log** (base) and **Meta Events Log**,
each row ending with the item's alias.

| Flag | Meaning |
| --- | --- |
| `--mini` | Only timestamp, event type, author (and tag name in the meta table). |

Without `--mini`, the base table adds node/edge IDs, source and target,
resource type and title; the meta table adds IDs, tag description,
source/target and underlying ID. Missing values show as `-`.

### `ik export`

Writes the base network as directed GraphML.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--output-path` | yes | Destination file (overwritten). |
| `--tags` | no | Comma-separated tags (UUIDs or aliases); keeps items carrying any of them. |

Each element carries `author`, `timestamp`, `blob_hash` and, for
`text/plain` content, a `label`. See [Known limitations](#known-limitations).

```bash
ik export --output-path theorems.graphml --tags m1,m4
```

### `ik ingest`

Bulk-creates nodes from a folder, then edges from a file.

| Flag | Meaning |
| --- | --- |
| `--input-folder` | Every entry (sorted, not recursive) becomes a node, read like `create_node --content`, titled by its stem. |
| `--edges-def-file` | One edge per line: `source,target,content` (split on the first two commas). |

```bash
printf 'e9,e1,cites\n' > edges.csv
ik ingest --input-folder ./more --edges-def-file edges.csv
```

### `ik transcribe`

Appends a signed `transcription` attesting the verified log.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--network` | `base` | `base` or `meta`; the event goes into that same log. |
| `--note` | none | Free text stored in the event. |

Prints `Transcription appended: <hash>` (the new head). An empty log fails:
`Nothing to transcribe: the <network> log is empty`.

```bash
ik transcribe --note "re-verified before release"
```

### `ik seal`

Fully verifies, then appends a signed seal of both logs and of the blobs they
reference. Prints `Seal <n> created: <hash>`: the string to publish. Refused
(exit 1) for an empty archive, an archive unchanged since the latest seal,
and while unreferenced blobs exist (the error lists the files to delete).

### `ik verify`

Re-reads and fully verifies the archive: both logs, every referenced blob,
every seal.

| Flag | Meaning |
| --- | --- |
| `--expect HASH` | Fail unless the seal log contains this seal. |

Prints `Archive verified: <n> base events, <m> meta events, <k> seals`, then
`Latest seal: <hash>` if any, and with `--expect`
`Expected seal found: seal <i> of <k>`. A failure exits 1 with its message,
e.g. `Expected seal not found in seal log`.

```bash
ik verify --expect "sha256:e1c0aa4631b1…"
```

### `ik fsck`

Fully verifies (whatever `--verify` says) and prints a report:

```text
Archive: /home/me/archives/demo
Base log: 10 events, head sha256:…
Meta log: 6 events, head sha256:…
Seals: 1, latest seal 1: sha256:…
Transcriptions: base 0, meta 0
Blobs: 9 files, 8 referenced, 1 unreferenced
  unreferenced (safe to delete): /home/me/archives/demo/blobs/sha256/4f/cc/4fcc…
Representations without a tag: 0
Verification: full, OK
```

### `ik manifest`

Writes `MANIFEST.json` at the archive root — format version, algorithms
used, the current author's public key (if any), layout, rules and JSON
Schemas of every log line — and copies `SPEC.md` and `test_vectors.json`
next to it. Prints `MANIFEST written to: <path>`. Re-run it after upgrading
`indiek` to refresh the copies.

### Example: a knowledge graph from scratch

With a folder holding `notes/statement.txt`, `notes/proof-sketch.md`,
`figures/diagram.png`, `scans/page.tiff` and `more/cites.txt`:

```bash
ik keygen --write
ik config --set-archive-path ~/archives/demo

ik create_node --content "Gödel's incompleteness theorem"            # e1
ik create_node --content ./notes/statement.txt                      # e2, title "statement"
ik create_node --content ./notes/proof-sketch.md --title "Proof"    # e3
ik create_node --content ./figures/diagram.png                      # e4
ik create_node --resource-type uri --uri https://arxiv.org/abs/1234.5678 \
  --title "Survey" --media-type "application/pdf; profile=pdfa"     # e5
ik create_node --resource-type local_file --path "$(realpath scans/page.tiff)"  # e6

ik create_edge --source-node e2 --target-node e1 --content "states"  # e7
ik create_edge --source-node e3 --target-node e2 --content "proves"  # e8
ik supersede_node --node-id e1 --content "Gödel's *first* incompleteness theorem"
ik supersede_edge --edge-id e8 --content "sketches a proof of"

ik create_node_tag --name theorem --description "A proven statement"  # m1
ik create_edge_tag --name proof --description "Proof relation"        # m2
ik set_tag --tag m1 --id e1   # m3 representation of e1, m4 assignment
ik set_tag --tag m2 --id e8   # m5 representation of e8, m6 assignment

printf 'e9,e1,cites\n' > edges.csv
ik ingest --input-folder ./more --edges-def-file edges.csv           # e9, e10

ik read --mini
ik export --output-path theorems.graphml --tags m1,m2
ik manifest
ik seal       # publish the printed hash
ik verify
```

## Integrity, seals and trust

### Integrity verification

Every command and every `Archive.open` verifies the archive before doing
anything: the base log, then the meta log, then the seal log, then the replay
into the index. Every event names its algorithms (`hash_alg: "sha256"`,
`sig_alg: "ed25519"`); hashes are written `sha256:<hex>`, signatures
`ed25519:<hex>`. A failure raises `IntegrityError` (CLI: exit 1) with one of:

| Message | Meaning |
| --- | --- |
| `Invalid log line: …` | A line is not UTF-8, not one JSON object, repeats a key, or holds a non-integer number or an integer outside ±(2^53−1). |
| `Invalid string: lone surrogate …` | A string is not valid Unicode. |
| `Unsupported format version …` | An event or seal is not format `3.0`. |
| `Unsupported algorithm …` | `hash_alg` / `sig_alg` missing or unknown. |
| `Algorithm mismatch …` | A signature or `prev_hash` does not carry the declared algorithm prefix. |
| `Chain broken!` | An event does not link to the previous one (edited, reordered, inserted or removed events). |
| `Data tampered or bad author!` | A signature does not verify against its author's key. |
| `File corrupted or missing!` | A referenced blob is absent or its bytes changed. |
| `Meta anchor does not match base history` | A meta event points to a base history that no longer exists (the base was rewritten or truncated). |
| `Meta anchor goes back in base history` | A meta event's anchor is older than the previous one's. |
| `Transcription does not match chain` | A transcription attests a head the log does not have. |
| `Seal chain broken!` | A seal is out of sequence, badly linked, badly signed or malformed. |
| `Seal does not match logs!` | A seal names a log tip that is not in the logs (rewritten or truncated, or `meta/` missing). |
| `Seal goes back in log history` | A seal covers fewer events than the previous one. |
| `Blob set does not match seal!` | A seal's `blob_root` does not match the blobs its events reference. |
| `Expected seal not found in seal log` | `--expect` / `--trust-seal` / `trusted_seal` names an absent seal. |
| `Supersede event references unknown item <id>` · `Supersede event type does not match item <id>` · `Supersede by a non-author of item <id>` · `Supersede edge events cannot change endpoints` · `Tag assignment references an unknown representation` | The logs verify but their content is inconsistent. |

**Meta anchors.** Every meta event records how many base events its author
had verified (`base_seq`) and the hash of the last one (`base_head`). If the
base is later rewritten or truncated, the base alone still verifies but every
annotation anchored past the change fails. Base events never mention the
meta log, so an archive shipped without `meta/` (and without `seals/`) is
valid on its own.

Some conditions only log a `WARNING`: unreferenced blobs, a seal of an empty
archive, a seal repeating the previous one, and (with `full` verification)
`SPEC.md` / `test_vectors.json` copies that differ from this package's.

### Seals and the blob store

A seal records the **base tip** and **meta tip** (event count and hash of the
last event) and `blob_root`, an RFC 6962 Merkle root of every blob those
events reference; it is signed and chained to the previous seal. The **seal
hash** commits to everything in the archive at that moment. Publish it (a web
page, an email, a printed book); anyone with a copy can check it with
`ik verify --expect <hash>`. No seal can prove it is the *latest* one:
freshness needs that outside reference.

Every seal, not only the latest, is checked on every open: chain and
signature, tips present in the logs, counts never decreasing, `blob_root`
recomputed. Writing after a seal is normal and keeps it valid; seal again for
a new checkpoint. `seals/` commits to both logs: ship it only together with
`events/` and `meta/`.

**Unreferenced blobs** are files under `blobs/sha256/` that no event uses —
the leftover of an interrupted write, or a file added by hand. They are not
part of the graph and no seal covers them. Opening warns
(`<n> unreferenced blob(s) in <dir> … : <names>`), sealing is refused until
they are deleted, and they are always safe to delete (`ik fsck` and
`Archive.unreferenced_blobs()` list them). A *referenced* blob that is
missing or altered always fails with `File corrupted or missing!`.

### Verification levels and the trust model

Most of the cost of opening an archive is checking the Ed25519 signature of
every event and re-hashing every blob. Measured on 10,000 events:

| Level (`--verify`, `verify=`) | What it does | 10k events |
| --- | --- | --- |
| `full` | Checks everything; ignores the cache, then refreshes it. | ≈ 11 s |
| `incremental` (default) | Recomputes every hash link, anchor, transcription and seal, but skips the signature checks and blob re-hashing that a trusted source already vouches for. | ≈ 1 s once cached |
| `none` | Parses only (debugging, recovering a damaged archive); the archive is read-only. | ≈ 0.3 s |

`verify`, `fsck`, `seal`, `ingest`, `export` and `manifest` always run a
`full` check first. At `incremental`, a damaged archive reports exactly the
error `full` would.

Checks may be skipped on exactly two grounds:

1. **Your machine checked it before.** After a successful check, the reader
   records "the signatures of events 1…N were valid and event N hashed to H"
   per log, plus the size and modification time of each verified blob. Next
   time it recomputes the chain anyway (cheap); if event N still hashes to H,
   events 1…N are byte-for-byte those already checked. Anything else, and the
   log is checked in full.
2. **A seal hash you obtained separately** (`--trust-seal HASH`,
   `trusted_seal=`), e.g. from the author's website. That seal must be in the
   seal log and the recomputed chains must reach its tips; only the
   signatures it covers are skipped.

**Never because of a seal found in the archive.** Any key may seal. If
Mallory alters Alice's event 500, re-links the events after it and seals the
result with his own key, a full check still fails (`Data tampered or bad
author!`): he cannot sign as Alice. Trusting seals found in the archive would
skip exactly that check, so IndieK always checks them and never trusts them.
With Alice's real seal hash, `--trust-seal` rejects Mallory's copy outright.

**The cache** lives outside the archive, in your user cache directory
(`~/Library/Caches/indiek/` on macOS, `$XDG_CACHE_HOME/indiek/` or
`~/.cache/indiek/` on Linux, `%LOCALAPPDATA%\indiek\Cache\` on Windows;
override with `IK_CACHE_DIR`), so nothing shipped with an archive can make
you skip a check. One small `state.json` per archive holds hashes, counts and
file sizes/times, never content; deleting it is always safe.

Caveats: the separate route for a trusted seal must be authenticated;
anyone who can write to your cache directory already controls your account;
and since the cache cannot see bit rot that keeps a file's size and time,
every blob is re-hashed whenever it is read, and `ik verify` / `ik fsck`
re-hash them all.

## Known limitations

- **One writer per history.** Each log is a single chain. Two copies extended
  independently cannot be merged (`Chain broken!`), and there is no lock
  against two local processes writing at the same moment.
- **Clock changes.** Events are filed by their UTC date; writing after the
  system clock moved back across midnight breaks the chain.
- **`local_file` paths** are absolute paths of the writer's machine.
- **CLI `--media-type`** is ignored for managed nodes (detected from the
  file name, or `text/plain`). PDF/A content can only be added from the SDK
  (`media_type=MediaType.APPLICATION_PDF_A`).
- **`export`** ignores supersedes (it shows original content), may keep an
  edge whose endpoint was filtered out, labels only `text/plain` content, and
  `--tags` fails with a `KeyError` on an archive whose base log holds a
  `transcription` event.
- **`ingest`** stores a subfolder's path as a text node, stops at the first
  hidden or unsupported file (e.g. `.DS_Store`), keeps the trailing newline
  in edge text, and crashes on an edge line with fewer than two commas.
- **`manifest`** lists only the current author in `authors`.
- **Reading content** goes through `archive.index.store.blobs`.
- **Schema checks on read** are partial: see `SPEC.md` §20.
- **Speed.** A `full` check of 10,000 events takes about 11 s.

## The archive format

The normative specification, `SPEC.md`, ships with the package
(`indiek/spec/SPEC.md`) and is written into archives by `ik manifest`; an
HTML version is on [indiek.org](https://indiek.org/docs/format/). In brief:

- logs are NDJSON, UTF-8, one event per line, read in path order;
- hashes and signatures are computed over canonical bytes: RFC 8785 (JCS)
  restricted to ASCII keys and integers in ±(2^53−1);
- an event is `{"header", "body", "signature"}`; the signature (Ed25519) covers
  header and body; `prev_hash` is the hash of the whole previous event;
- blobs live at `blobs/sha256/<2>/<2>/<hex>`;
- meta events anchor to the base; seals commit to both logs and a Merkle
  root of the referenced blobs;
- `test_vectors.json` lets an independent implementation check itself.

## Contributing

Contributions open on **1 November 2026**; see
[indiek.org/docs/contributing](https://indiek.org/docs/contributing/).

```bash
uv sync                              # dev environment (includes the cli extra)
uv run pytest                        # test suite (uv run pytest -m slow for the 10k-event test)
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts
```

Every change comes with tests and a `CHANGELOG.md` entry. After a format
change, regenerate the test vectors with
`uv run python scripts/make_test_vectors.py` and update `SPEC.md`.

## License

Copyright 2026 Adrian Ernesto Radillo. Licensed under the
[Apache License, Version 2.0](LICENSE).
