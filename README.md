See [indiek.org](https://indiek.org) for broader context and documentation on the IndieK project.
# SDK summary notes
## Reading an archive
To load an existing archive, read-only, from your hard-drive, do the following.
```python
from indiek import Archive
ik = Archive.open("/foo/bar/your_archive")
```
In the SDK, "items" are events. You may inspect them as a list of `indiek.core.index.IndexedItem` with:
```python
items = list(ik.index.items.values())
first_event = items[0]
```
### Inspecting a text blob
Assuming your first event was the creation of a node with text data type, you may read the text with:
```python
from indiek.core.models import MediaType
text_types = {MediaType.TEXT_PLAIN.value, MediaType.TEXT_MARKDOWN.value}
if (item_media:=first_event.body['media_type']) in text_types:
    ik.index.store.blobs.get_text(first_event.body['blob_hash'])
else:
    print(item_media, "is not a text media type")
```
### Inspecting an edge
Below is a REPL illustrating how to display the text blob associated
with the source and target nodes of the first edge from the `items` list above.
```python
>>> from indiek.core.index import ItemKind
>>> for i in items:
...     if i.kind == ItemKind.EDGE:
...         break
...         
>>> i  # the edge
IndexedItem(id=UUID('01a14a3a-0b6a-76a3-a0e4-de4eeb1d3705'), alias='e7', kind=<ItemKind.EDGE: 'edge'>, author='d2d39654817d03df5510a0a7e3a82b621b500774693d3f33bb150aadb4158100', body={'event_type': 'create_edge', 'resource_type': 'managed', 'media_type': 'text/plain; charset=utf-8', 'blob_hash': 'sha256:923b4b90ea64343e4a1cc2386c52fb2c0d197b0673cffbf1197169c27c8e4eb9', 'uri': None, 'path': None, 'file_size': None, 'file_hash': None, 'last_verified': None, 'title': None, 'body_type': 'edge', 'edge_id': '01a14a3a-0b6a-76a3-a0e4-de4eeb1d3705', 'source_node': '01a14a3a-071c-7192-81c8-3508c77d385f', 'target_node': '01a14a3a-0645-753b-8414-2deab807aeaa'}, tags=set())
>>> source_target = [create_node for create_node in items if str(create_node.id) in { '01a14a3a-071c-7192-81c8-3508c77d385f', '01a14a3a-0645-753b-8414-2deab807aeaa'}]
>>> len(source_target)
2
>>> ik.index.store.blobs.get_text(i.body['blob_hash'])  # the edge label 
'states'
>>> ik.index.store.blobs.get_text(source_target[0].body['blob_hash'])  # source node text
"Gödel's *first* incompleteness theorem"
>>> ik.index.store.blobs.get_text(source_target[1].body['blob_hash'])  # target node text
'The thm stateemnt\n'
```

# `ik` CLI — API Reference

Reference for all sixteen `ik` subcommands. The Python SDK behind them
(`import indiek`) is documented in the docstrings of `indiek.Archive`.

| Command | Purpose | Prints on success |
| --- | --- | --- |
| `config` | Show / set `IK_ARCHIVE_PATH` in the dotenv file | `IK_ARCHIVE_PATH=<value>` |
| `keygen` | Generate an Ed25519 author key | `IK_AUTHOR_PRIVATE_KEY=<seed>` (nothing with `--write`) |
| `create_node` | Add a base-network node (`managed`, `uri`, `local_file`) | `Node created: <uuid>` |
| `create_edge` | Add a directed, content-carrying edge between two nodes | `Edge created: <uuid>` |
| `supersede_node` | Replace a node's content (append-only) | `Node superseded: <uuid>` |
| `supersede_edge` | Replace an edge's content (append-only) | `Edge superseded: <uuid>` |
| `create_node_tag` | Define a tag for nodes | nothing |
| `create_edge_tag` | Define a tag for edges | `Meta node created: <uuid>` |
| `set_tag` | Attach a tag to a node or edge | nothing |
| `read` | Print the base and meta event logs as tables | two tables |
| `export` | Write the base network as GraphML | nothing |
| `ingest` | Bulk-create nodes from a folder and edges from a file | nothing |
| `manifest` | Write `MANIFEST.json` at the archive root | `MANIFEST written to: <path>` |
| `transcribe` | Attest the verified base or meta log with a signed `transcription` event | `Transcription appended: <hash>` |
| `seal` | Append a signed seal committing to both logs and their blobs | `Seal <n> created: <hash>` |
| `verify` | Fully re-verify the archive, optionally requiring a known seal | counts and the latest seal hash |

## Install

```bash
uv tool install 'indiek[cli]'   # the ik command (adds rich + python-dotenv)
uv add indiek                   # the SDK only
```

Until the PyPI release, install from a checkout of this folder:
`uv tool install --editable '.[cli]'`.

## Invocation shape

```
ik [--dot-env PATH] [--logging-level LEVEL] <command> [flags]
```

Global flags apply to every command and must precede the subcommand.

| Flag | Required | Default | Meaning |
| --- | --- | --- | --- |
| `--dot-env` | no | `.env` | Dotenv file to load. Loaded with `override=False`, so real environment variables win. |
| `--logging-level` | no | `WARNING` | A `logging` level name, case-insensitive: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. Any other name exits with status 2. |

All log output is written to **stderr**. Stdout carries only command output
(printed IDs, tables, `config` / `keygen` lines), so it is safe to pipe.

### Environment

| Variable                | Meaning                                                                    |
| ----------------------- | -------------------------------------------------------------------------- |
| `IK_ARCHIVE_PATH`       | Root directory of the archive.                                             |
| `IK_AUTHOR_PRIVATE_KEY` | Current author's Ed25519 private key: a 32-byte seed as 64 hex characters. |

Which commands need what:

- `config` and `keygen` need neither variable.
- `read`, `export` and `manifest` need only `IK_ARCHIVE_PATH`. Without a key the
  archive is opened read-only and `manifest` lists no author.
- Every other command also needs the key; without it the write fails with
  `AuthorshipError: An author is required to write to an archive`.

A missing `IK_ARCHIVE_PATH` exits with status 2; a leading `~` is expanded. A
malformed key (non-hex, or not 32 bytes) exits with status 1 and
`ik: error: IK_AUTHOR_PRIVATE_KEY is invalid: <reason>`; the key itself is never printed.
Generate a key with [`ik keygen`](#ik-keygen).

### Errors and exit codes

| Exit status | Meaning |
| ----------- | ------- |
| `0` | Success. |
| `1` | The command failed (integrity, unknown item, authorship, archive rule, invalid key). One line `ik: error: <message>` is printed on stderr, with no traceback; `--logging-level DEBUG` adds the traceback. |
| `2` | Usage error from argument parsing: missing or invalid flag, or `IK_ARCHIVE_PATH` not set. |

Messages quoted below as `ErrorClass: message` are the exceptions raised by the
Python SDK (`indiek.IndieKError` and subclasses); the CLI prints the same
`message` after `ik: error:`.

### Integrity verification

Every command that opens the archive (all but `config` and `keygen`) walks and
verifies the whole event log, the whole meta event log **and** the seal log
before running. There is no way to skip verification.
Every event names its algorithms in `header.hash_alg` (`sha256`) and
`header.sig_alg` (`ed25519`). Hashes and signatures are written with the
algorithm as a prefix: `prev_hash` and archive heads are `sha256:<hex>`,
signatures are `ed25519:<hex>`, blob hashes are `sha256:<hex>`.

Verification raises `IntegrityError` with one of these messages:

- `Unsupported algorithm …` — `hash_alg` or `sig_alg` is missing or unknown.
- `Algorithm mismatch …` — the `signature`, or a non-null `prev_hash`, does not carry the header's algorithm as prefix (a bare hex value included).
- `Chain broken!` — a `header.prev_hash` does not match the canonical hash of the preceding event.
- `Data tampered or bad author!` — the Ed25519 signature does not verify against `header.author`.
- `File corrupted or missing!` — an event's `blob_hash` is absent from the blob store or its bytes hash to something else.
- `Meta anchor does not match base history` — a meta event's anchor (see below) names a base event that does not exist or hashes to something else.
- `Meta anchor goes back in base history` — a meta event's `base_seq` is lower than the previous meta event's.
- `Transcription does not match chain` — a `transcription` event's `verified_head` is not the hash of event number `verified_count` of its log (see [`ik transcribe`](#ik-transcribe)).
- `Seal chain broken!` — a seal's `seq` is not its position, its `prev_seal_hash` is not the hash of the previous seal (or the first seal is missing), its signature does not verify, or it is malformed.
- `Seal does not match logs!` — a seal names a base or meta tip that is not in the verified log (the log was rewritten or truncated after the seal, or `meta/` is missing).
- `Seal goes back in log history` — a seal's base or meta count is lower than the previous seal's.
- `Blob set does not match seal!` — a seal's `blob_root` is not the Merkle root of the blobs referenced by the events it covers (see [Seals and the blob store](#seals-and-the-blob-store)).

**Meta anchors.** Every meta event header records `base_seq`, the number of
base events its author had verified, and `base_head`, the hash of base event
number `base_seq` (`null` when `base_seq` is 0). The base log is verified
first; if its author later rewrites or truncates it, the base alone still
verifies but every meta event anchored past the change fails. The anchor is
one-way: base events never mention the meta log, so an archive shipped
without `meta/` is valid on its own (drop `seals/` too: seals commit to both
logs), and anyone may annotate someone else's base with their own key.

Building the index then raises `IntegrityError` if the logs are inconsistent:

- `Supersede event references unknown item <id>`
- `Supersede event type does not match item <id>`
- `Supersede edge events cannot change endpoints`
- `Supersede by a non-author of item <id>`
- `Tag assignment references an unknown representation`

A successful verification logs `ARCHIVE INTEGRITY VERIFIED` at `INFO`, on
stderr (visible with `--logging-level info`).

Some conditions are reported as a `WARNING` on stderr but do **not** fail
verification: unreferenced blobs, a seal of an empty archive, and a seal that
repeats the previous one (see below).

### Seals and the blob store

A **seal** is a signed snapshot of the whole archive, appended as one line to
`seals/seals.ndjson`. It records:

- the **base tip** and the **meta tip**: how many events each log had
  (`count`) and the hash of the last of them (`head`);
- `blob_root`: one hash summarising **every blob those events reference**
  (an RFC 6962 Merkle root, the same construction as Certificate Transparency);
- `seq` (1, 2, 3, …), `prev_seal_hash` (the previous seal's hash, so seals
  form their own chain), `time`, the sealing `key` and its signature `sig`.

The **seal hash** (`sha256:…`, printed by `ik seal`) is the one short string
that commits to everything in the archive at that moment. Publish it (on a
web page, in an email, in a printed book); anyone holding a copy of the
archive can then check that copy against it with
`ik verify --expect <seal hash>`. A seal cannot prove that it is the *latest*
one: freshness always needs such an outside reference.

**What is checked, every time the archive is opened.** Every seal, not only
the latest, is checked exactly:

1. it is the next link of the seal chain and its signature verifies;
2. its base and meta tips exist, with those hashes, in the verified logs;
3. its counts are not lower than the previous seal's;
4. its `blob_root` equals the Merkle root recomputed from the blobs referenced
   by the events it covers.

Adding nodes, edges or tags after a seal is normal and keeps every existing
seal valid: a seal only speaks about the events up to its own counts. Seal
again whenever you want a new checkpoint.

**Unreferenced blobs.** A blob is *unreferenced* when it sits under
`blobs/sha256/` but no event points to it. Two things produce one:

- an **interrupted write**: the program stopped after saving the file and
  before recording the event that uses it (a crash, a killed process, a full
  disk);
- a file **added by hand**, or by another tool, possibly to smuggle content
  into the archive.

Unreferenced blobs are never part of the knowledge graph and no seal covers
them. They are handled like git handles dangling objects:

- **Opening the archive warns, it does not fail.** Every command logs, at
  `WARNING` level on stderr,
  `<n> unreferenced blob(s) in <blob dir> (no event uses them; delete them before sealing): <names>`,
  and still runs (silence it with `--logging-level ERROR`). An interrupted write can therefore never make an
  archive unusable, and a file slipped in after a seal is always reported.
- **Sealing is refused while any exist**, with
  `ArchiveRuleError: Cannot seal: <n> unreferenced blob(s) … Delete them and seal again: <paths>`.
  A seal is a statement about the whole archive; refusing keeps it from
  silently covering a file nobody accounted for.
- **They are safe to delete**: no event and no seal depends on them. Delete
  the paths listed in the warning or the error, or list them from Python with
  `Archive.open(path).unreferenced_blobs()`. If you want to keep the content,
  add it as a node instead (the blob is reused, not duplicated).

What this does **not** relax: a blob that an event references is re-hashed on
every open, and a missing or altered one still fails with
`File corrupted or missing!`, seal or no seal.

**Read-time warnings for unusual seals.** `ik seal` refuses to seal an empty
archive and to seal an archive unchanged since the latest seal. A seal log
written by other software may still contain such seals; they are valid, and
opening the archive only logs, at `WARNING` level,
`Seal <n> seals an empty archive` or
`Seal <n> repeats seal <m> (the archive did not change)`.

**Shipping parts of an archive.** `seals/` commits to the base and meta logs
together: ship it only with both `events/` and `meta/`. Without `meta/`,
the seals fail with `Seal does not match logs!`; drop `seals/` as well and the
base verifies on its own.

## Identifiers

Every item is addressed by a UUIDv7. In addition, the index assigns
human-friendly aliases by replaying the logs in order:

- **Base network** — creations get `e1`, `e2`, `e3`, … in event order. The `e`
  prefix is used for **both nodes and edges**; there is no `n` prefix. `e4` may
  well be a node.
- **Meta network** — creations get `m1`, `m2`, `m3`, …. Tags, representations
  **and** `set_edge_tag` / `set_node_tag` events each consume a number, so
  meta numbering is not a tag counter.
- `supersede_*` events do not allocate a new alias; they replace the projection
  of the existing one.

Any flag documented as accepting an ID accepts either a UUID string or a
human-friendly alias. A string that is neither a known alias nor a UUID raises
`UnknownItemError: Unknown ID or alias '<ref>'` (a `ValueError`).

---

## `ik create_node`

Appends a `create_node` event to the base event log.

| Flag | Required | Default | Meaning |
| --- | --- | --- | --- |
| `--content` | for `managed` only | — | Inline text, or a path to a supported file. |
| `--title` | no | see below | Human-readable title stored in the event body. |
| `--resource-type` | no | `managed` | One of `managed`, `uri`, `local_file`. |
| `--uri` | for `uri` only | — | External URL. Never fetched. |
| `--path` | for `local_file` only | — | Local file path. Never copied into the archive. |
| `--media-type` | no | — | One of `text/plain; charset=utf-8`, `text/markdown; charset=utf-8`, `image/tiff`, `image/png`, `image/jpeg`, `application/pdf; profile=pdfa`. |

Prints `Node created: <uuid>` on success.

`--media-type` is validated by argparse `choices`: any other value exits with
status 2 before the archive is touched.

If `--title` is omitted and `--content` names an existing file, the title
defaults to that file's stem — for **every** resource type, even `uri` and
`local_file` nodes where `--content` is otherwise ignored.

### `--resource-type managed` (default)

The content is copied into the archive's content-addressed blob store and the
event records only `blob_hash` + `media_type`.

`--content` is interpreted as follows:

- If it names an existing file: the file is read. `text/plain` and
  `text/markdown` files are read as UTF-8 text; other supported types are read
  as bytes. The media type is inferred from the filename via `mimetypes`, and
  only `text/plain`, `text/markdown`, `image/jpeg`, `image/png`, `image/tiff`
  are accepted — anything else raises
  `ValueError: Unsupported archival media type for <path>`. Note that
  `application/pdf; profile=pdfa` is a legal media type in the format but is
  **not** reachable through file detection.
- Otherwise it is treated as literal UTF-8 text with media type `text/plain`.

**`--media-type` is ignored for managed nodes.** The value you pass is
overwritten by the detection step above. Omitting `--content` is an argparse
error: `create_node --content is required for managed nodes`.

Otherwise (no `--title`, `--content` is inline text) the title is `null`.

```bash
ik create_node --content "Gödel's incompleteness theorem"
ik create_node --content ./notes/limits.md --title "Limits"
```

### `--resource-type uri`

Records a reference to an external URL. No network access, no blob is written.
`--media-type` **is** honoured here and stored as a hint; it may be omitted.
`--content` and `--path` are ignored. Missing `--uri` is a usage
error (exit 2): `--uri is required when --resource-type uri`.

```bash
ik create_node --resource-type uri --uri https://arxiv.org/abs/1234.5678 \
  --title "The paper" --media-type "application/pdf; profile=pdfa"
```

### `--resource-type local_file`

Records a pointer to a file on this machine plus enough data to detect drift
later. The path is expanded (`~`) and resolved to an absolute path; the file is
read once to compute `file_size` and `file_hash` (SHA-256), and
`last_verified` is stamped with the current UTC time. The bytes are **not**
copied into the blob store.

The media type is detected from the filename with the same restricted mapping
as managed files, so unsupported extensions fail here too. `--title` defaults
to the file stem. A missing or non-regular file raises
`ValueError: Local file does not exist or is not a regular file: <path>`, and a
missing `--path` is a usage error (exit 2): `--path is required when --resource-type local_file`.

```bash
ik create_node --resource-type local_file --path ~/scans/page.tiff
```

---

## `ik create_edge`

Appends a `create_edge` event: a directed edge from source to target that
itself carries content.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--content` | yes | Text content attached to the edge. |
| `--source-node` | yes | Source ID (UUID or alias). |
| `--target-node` | yes | Target ID (UUID or alias). |

Semantics and limits:

- The content is **always** stored as `text/plain; charset=utf-8`. There is no
  media-type flag, and unlike `create_node --content`, a value that happens to
  be a file path is stored verbatim as text — the file is not read.
- Both endpoints are resolved as aliases or UUIDs; an unknown alias raises
  `UnknownItemError: Unknown ID or alias '<ref>'`.
- Both endpoints **are** checked at write time: each must be an existing
  base-network **node**, otherwise the command raises
  `UnknownItemError: SOURCE NODE <uuid> NOT FOUND IN ARCHIVE` or
  `UnknownItemError: TARGET NODE <uuid> NOT FOUND IN ARCHIVE`. Edges and tags
  can never be endpoints.
- Endpoints are validated *before* the content blob is written, so a failed
  `create_edge` writes nothing.
- Edges are directed. Endpoints are immutable: `supersede_edge` may replace an
  edge's content but the index rejects any attempt to change `source_node` or
  `target_node`.
- Prints `Edge created: <uuid>` on success. Use `ik read` to recover the new `e{n}` alias.

```bash
ik create_edge --content "generalises" --source-node e1 --target-node e2
```

---

## `ik supersede_node`

Appends a `supersede_node` event that replaces a node's content. History is
kept: the original event stays in the log.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--node-id` | yes | Node to supersede (UUID or `e{n}` alias). |
| `--content` | yes | Replacement content, stored as literal text. |
| `--title` | no | New title. When omitted, the node's latest title is kept. |

Semantics:

- The replacement is always a **managed** blob with media type
  `text/markdown; charset=utf-8`, whatever the node's original resource type.
- The node keeps its UUID and its `e{n}` alias.
- Errors: `ValueError: Node '<id>' does not exist in this archive` and
  `ValueError: ID '<id>' does not reference a base-network node`.
- Only the node's author (the key that created it) may supersede it; any other
  key fails with `AuthorshipError: Only the author of Node '<id>' may supersede it`
  before anything is written. To disagree with someone else's node, create your
  own node and an edge to theirs. A log containing a supersede signed by
  another key fails verification with
  `IntegrityError: Supersede by a non-author of item <uuid>`.
- Prints `Node superseded: <uuid>`.

```bash
ik supersede_node --node-id e1 --content "Gödel's *first* incompleteness theorem"
```

---

## `ik supersede_edge`

Appends a `supersede_edge` event that replaces an edge's content.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--edge-id` | yes | Edge to supersede (UUID or `e{n}` alias). |
| `--content` | yes | Replacement text. |

Semantics:

- The replacement is always stored as `text/plain; charset=utf-8`.
- `source_node`, `target_node` and `title` are copied from the current edge;
  endpoints can never change.
- Errors: `ValueError: Edge '<id>' does not exist in this archive` and
  `ValueError: ID '<id>' does not reference a base-network edge`.
- Only the edge's author may supersede it, as for `supersede_node`
  (`AuthorshipError: Only the author of Edge '<id>' may supersede it`).
- Prints `Edge superseded: <uuid>`.

```bash
ik supersede_edge --edge-id e3 --content "strictly generalises"
```

---

## `ik create_edge_tag`

Appends a `create_edge_tag` event to the **meta** event log, defining a tag
intended for edges. It creates only the tag definition — it does not attach the
tag to anything.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--name` | yes | Tag name. |
| `--description` | yes | Tag description. Mandatory, not optional. |

Notes:

- Tag vocabulary is entirely user-defined; no name is reserved and names are
  not checked for uniqueness. Creating the same name twice yields two distinct
  tag nodes.
- The tag is written with the current author's public key. That author is the
  only one who may later use it — see `set_tag`.
- The new tag receives the next `m{n}` alias.
- Prints `Meta node created: <uuid>` on success.

```bash
ik create_edge_tag --name "conjecture" --description "Unproven claimed relation"
```

---

## `ik create_node_tag`

Same flags and notes as `create_edge_tag`, except that it appends a
`create_node_tag` event, defining a tag intended for **nodes**, and it **prints
nothing** on success (use `ik read` to find the new `m{n}` alias). Only node
tags can be attached to nodes — see `set_tag`.

```bash
ik create_node_tag --name "theorem" --description "A proven statement"
```

---

## `ik set_tag`

Attaches an existing tag to an existing base-network node or edge by appending
a meta edge from the tag to a *representation* of the target.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--tag` | yes | ID of the tag (UUID or `m{n}` alias). Becomes the meta edge's source. |
| `--id` | yes | ID of the base-network node or edge to tag (UUID or `e{n}` alias). |

Sequence of operations:

1. Resolve `--tag` and assert it is a meta node created by `create_edge_tag` or
   `create_node_tag` — otherwise `ValueError: <uuid> is not a tag node`.
2. Assert the current author's public key equals the tag's author — otherwise
   `ValueError: Only the tag's author may use this operation`.
3. Resolve `--id` and require it to exist in the index
   (`ValueError: UUID is not part of any network (neither base nor meta)`) and
   to belong to the base network
   (`ValueError: UUID should not be an item from the meta network`).
4. If the target has no representation yet, append a
   `create_edge_representation` or `create_node_representation` meta event
   (chosen by whether the target is an edge), then reload and re-index the
   archive. This is transparent but means a first-time `set_tag` writes **two**
   meta events and consumes two `m{n}` aliases.
5. Append a `set_edge_tag` / `set_node_tag` meta edge from the tag node to the
   representation node.

Notes:

- The tag kind must match the target kind: an edge tag can only be applied to
  an edge, and a node tag only to a node. Otherwise step 5 raises
  `ValueError: An edge tag should point to an edge representation` or
  `ValueError: A node tag should point to a node representation`.
- Because that check runs in step 5, a rejected first-time `set_tag` still
  leaves the representation event from step 4 in the meta log (consuming one
  `m{n}` alias). No meta edge is written. This is **intended**: the
  representation is harmless and is reused by any later `set_tag` on the same
  target. When it happens, a `WARNING` naming the representation and target
  UUIDs is logged before the `ValueError` is raised (silence it with
  `--logging-level ERROR`). No warning is logged if the target already had a
  representation, since nothing is written in that case.
- Re-running `set_tag` with the same pair appends another meta edge; the
  projected tag set is a set, so the result is idempotent in effect but not in
  the log.
- Prints nothing on success.

```bash
ik create_node --content "Gödel's incompleteness theorem"   # e1
ik create_node_tag --name "theorem" --description "A proven statement"   # m1
ik set_tag --tag m1 --id e1   # m2 = representation of e1, m3 = meta edge
```

---

## `ik read`

Prints the archive as two `rich` tables on stdout: **Events Log** (base
network) and **Meta Events Log**. Every row ends with a *Human-Friendly ID*
column (`e{n}` / `m{n}`).

| Flag | Required | Meaning |
| --- | --- | --- |
| `--mini` | no | Compact view: only Timestamp, Event Type, Author (+ Tag Name in the meta table). |

Without `--mini` the base table adds Node ID, Edge ID, Source Node, Target
Node, Resource Type and Title; the meta table adds Meta Node ID, Meta Edge ID,
Tag Description, Meta Source/Target Node and Underlying ID. Missing values are
shown as `-`.

```bash
ik read --mini
```

---

## `ik export`

Writes the base network as a pretty-printed, directed GraphML file.

| Flag | Required | Default | Meaning |
| --- | --- | --- | --- |
| `--output-path` | yes | — | Destination `.graphml` file (overwritten). |
| `--tags` | no | none | Comma-separated tag IDs (UUIDs or `m{n}` aliases). |

Semantics and limits:

- Only `create_node` and `create_edge` events become `<node>` / `<edge>`
  elements. **Supersede events are ignored**, so the export shows original
  content.
- Each element carries `author`, `timestamp`, `blob_hash`, and a `label` —
  the label is only filled for `text/plain` content.
- `--tags` keeps an item if it carries **any** of the listed tags (OR). Nodes
  and edges are filtered independently, so an exported edge may point at a node
  that was filtered out.
- An unknown alias in `--tags` raises `UnknownItemError`.
- Prints nothing on success.

```bash
ik export --output-path graph.graphml --tags m1,m4
```

---

## `ik ingest`

Bulk-creates managed nodes from a folder, then edges from a definition file.
Both flags are optional; with neither, nothing happens.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--input-folder` | no | Every entry of this folder (sorted, **not** recursive) becomes a node. |
| `--edges-def-file` | no | One edge per line: `source,target,content`. |

Semantics and limits:

- Each entry goes through the same detection as `create_node --content`; the
  node title is the file stem.
- Hidden and unsupported files (e.g. `.DS_Store`) raise
  `Unsupported archival media type` and abort the run; nodes already created
  stay in the archive.
- A **subdirectory** is not a file, so its path string is stored as a
  `text/plain` node.
- Edge lines split on the first two commas; the content may contain further
  commas. Source and target accept UUIDs or `e{n}` aliases. The line's trailing
  newline is **kept** in the edge content. A line with fewer than two commas
  crashes.
- Prints nothing on success.

```bash
printf 'e1,e2,generalises\n' > edges.csv
ik ingest --input-folder ./notes --edges-def-file edges.csv
```

---

## `ik manifest`

Writes (overwrites) `MANIFEST.json` at the archive root: format name and
version, the current author's public key, the blob-store and event-log layout,
and JSON schemas of the event models. No flags. Prints
`MANIFEST written to: <path>`.

Known wording bug: the manifest describes the canonical serialisation as
"compact JSON"; the implementation actually uses `json.dumps(..., sort_keys=True)`
with Python's default `", "` / `": "` separators.

```bash
ik manifest
```

---

## `ik transcribe`

Appends a signed `transcription` event attesting the log as just verified:
"I verified this log up to head H (its first N events) under algorithms A, now."
Algorithms age; generations of transcriptions under newer algorithms are how
a chain of custody outlives the ones it started with.

| Flag | Required | Default | Meaning |
| --- | --- | --- | --- |
| `--network` | no | `base` | Log to attest, `base` or `meta`. The event is appended to **that same log**; it never attests the other one. |
| `--note` | no | none | Free text stored in the event. |

- The body records `verified_head`, `verified_count`, `verified_hash_alg`,
  `verified_sig_alg`, `verified_at` (UTC) and `note`.
- It allocates no `e{n}` / `m{n}` alias and changes no node, edge or tag.
- Any author may transcribe any archive; a key is required.
- An empty log cannot be transcribed:
  `ArchiveRuleError: Nothing to transcribe: the <network> log is empty` (exit 1).
- Prints `Transcription appended: <hash>`, the new head of that log.
- SDK: `ik.transcribe(network="base", note=None)`; records are listed in
  `ik.index.transcriptions["base"]` / `["meta"]`.

```bash
ik transcribe --note "re-verified before release"
ik transcribe --network meta
```

---

## `ik seal`

Re-verifies the whole archive, then appends a signed seal of the base tip,
the meta tip and the blobs they reference to `seals/seals.ndjson` (see
[Seals and the blob store](#seals-and-the-blob-store)). No flags.

- Prints `Seal <n> created: <hash>`. The hash is the string to publish.
- Any key may seal; a key is required.
- Refused (exit 1) when the archive is empty
  (`Nothing to seal: the archive is empty`), unchanged since the latest seal
  (`Nothing to seal: the archive is unchanged since seal <n>`), or holding
  unreferenced blobs (`Cannot seal: <n> unreferenced blob(s) …`, with the
  paths to delete).
- SDK: `ik.seal()` returns an `indiek.Seal` (`hash`, `seq`, `prev_seal_hash`,
  `base_head`, `base_count`, `meta_head`, `meta_count`, `blob_root`, `time`,
  `key`); `ik.seals()` lists every verified seal, oldest first.

```bash
ik seal
```

---

## `ik verify`

Re-reads and fully re-verifies the archive: both event logs, every
referenced blob, and every seal.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--expect` | no | A seal hash. Fails unless the seal log contains it. |

- Prints `Archive verified: <n> base events, <m> meta events, <k> seals`,
  then `Latest seal: <hash>` when there is one, and with `--expect`
  `Expected seal found: seal <i> of <k>`.
- Any integrity failure exits 1 with its `IntegrityError` message; an absent
  expected seal exits 1 with `Expected seal not found in seal log`.
- SDK: `ik.verify(expect=None)` returns the expected seal, or the latest one
  (`None` without seals).

```bash
ik verify --expect "$PUBLISHED_SEAL_HASH"   # e.g. sha256:e1c0aa46…
```

---

## `ik config`

Shows, and optionally sets, `IK_ARCHIVE_PATH` in the dotenv file given by
`--dot-env`. It needs neither a key nor an existing archive, so it can
bootstrap a fresh setup.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--set-archive-path` | no | New archive path to write into the dotenv file. |

- Prints `IK_ARCHIVE_PATH=<value>` (from the environment or the dotenv file) or
  `IK_ARCHIVE_PATH is not set`; when setting, then prints `IK_ARCHIVE_PATH=<path>`.
- The value is written with `dotenv.set_key`, which wraps it in single quotes.
- Only `IK_ARCHIVE_PATH` can be set here; use `ik keygen --write` for the key.

```bash
ik --dot-env .env config --set-archive-path ~/archives/mykg
```

---

## `ik keygen`

Generates a fresh Ed25519 author key. Needs neither a key nor an archive.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--write` | no | Store the seed in the `--dot-env` file (file mode set to `600`) instead of printing it. |
| `--force` | no | With `--write`, replace an `IK_AUTHOR_PRIVATE_KEY` already in that file. The old key is lost. |

- Without `--write`: prints `IK_AUTHOR_PRIVATE_KEY=<64 hex chars>` on stdout,
  ready to append to a dotenv file, and `Public key: <hex>` on stderr.
- With `--write`: prints nothing on stdout; stderr names the file and the
  public key. If the file already defines the key and `--force` is absent, it
  exits with status 1 and leaves the file untouched.
- The seed is the only secret: never commit it. The public key is what appears
  as `header.author` in events and in `MANIFEST.json`.

```bash
ik --dot-env .env keygen --write
```

---

## Example: build a knowledge graph from scratch

One session exercising every command. Comments show the alias each step
allocates in a fresh archive.

Before running the bash script below, populate a kg-demo-0110/ folder with 
a similar subtree of files and folders as the one below:

```
/foo/bar/kg-demo-0110/
├── figures
│   └── diagram.png
├── more
│   └── andtext.txt
├── notes
│   ├── proof-sketch.md
│   └── statement.txt
├── scans
│   └── atiffimage.tiff
```

Contents of a demo bash script to create a knowledge graph archive from scratch below.

```
#!/bin/bash
cd /foo/bar/kg-demo-0110   # a folder holding the sample files below
ik keygen --write
ik config --set-archive-path ~/tmp/archives/demo-0110

# 2. Managed nodes: inline text, text/plain, text/markdown, image/png
ik create_node --content "Gödel's incompleteness theorem"            # e1
ik create_node --content ./notes/statement.txt                      # e2 (title "statement")
ik create_node --content ./notes/proof-sketch.md --title "Proof"    # e3
ik create_node --content ./figures/diagram.png                      # e4

# 3. Reference nodes: uri and local_file
ik create_node --resource-type uri --uri https://arxiv.org/abs/1234.5678 \
  --title "Survey" --media-type "application/pdf; profile=pdfa"     # e5
ik create_node --resource-type local_file --path $(realpath .)/scans/atiffimage.tiff  # e6

# 4. Edges, then append-only revisions
ik create_edge --source-node e2 --target-node e1 --content "states"  # e7
ik create_edge --source-node e3 --target-node e2 --content "proves"  # e8
ik supersede_node --node-id e1 --content "Gödel's *first* incompleteness theorem"
ik supersede_edge --edge-id e8 --content "sketches a proof of"

# 5. Tags
ik create_node_tag --name theorem --description "A proven statement"  # m1
ik create_edge_tag --name proof --description "Proof relation"        # m2
ik set_tag --tag m1 --id e1   # m3 = representation of e1, m4 = meta edge
ik set_tag --tag m2 --id e8   # m5 = representation of e8, m6 = meta edge

# 6. Bulk import: one .txt in ./more becomes e9; the edge line becomes e10
printf 'e9,e1,cites\n' > edges.csv
ik ingest --input-folder ./more --edges-def-file edges.csv

# 7. Inspect, export, document, seal
ik read --mini
ik export --output-path theorems.graphml --tags m1,m2
ik manifest
ik seal      # prints the seal hash to publish
ik verify
```
