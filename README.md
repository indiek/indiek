# `ik` CLI — API Reference

Reference for four commands: `create_node`, `create_edge`, `create_edge_tag`, `set_tag`.

## Invocation shape

```
ik [--dot-env PATH] [--logging-level LEVEL] <command> [flags]
```

Global flags apply to every command and must precede the subcommand.

| Flag | Required | Default | Meaning |
| --- | --- | --- | --- |
| `--dot-env` | no | `.env` | Dotenv file to load. Loaded with `override=False`, so real environment variables win. |
| `--logging-level` | no | `WARNING` | Any `logging` level name (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). |

Every invocation reads `IK_ARCHIVE_PATH` and `IK_AUTHOR_PRIVATE_KEY` from the
environment, then walks and verifies the whole event log **and** the whole meta
event log before dispatching the command. There is no way to skip verification.
Verification raises `IntegrityError` with one of three messages:

- `Chain broken!` — a `header.prev_hash` does not match the canonical hash of the preceding event.
- `Data tampered or bad author!` — the Ed25519 signature does not verify against `header.author`.
- `File corrupted or missing!` — an event's `blob_hash` is absent from the blob store or its bytes hash to something else.

At `WARNING` level (the default) a successful verification prints
`ARCHIVE INTEGRITY VERIFIED` to stdout.

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
human-friendly alias. Resolution is a plain dictionary lookup: an unknown alias
is passed through to `UUID(...)` and fails with a `ValueError` about a badly
formed hexadecimal UUID string.

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

If `--title` is omitted and `--content` names an existing file, the title
defaults to the file's stem (filename without extension). Otherwise the title
is `null`.

```bash
ik create_node --content "Gödel's incompleteness theorem"
ik create_node --content ./notes/limits.md --title "Limits"
```

### `--resource-type uri`

Records a reference to an external URL. No network access, no blob is written.
`--media-type` **is** honoured here and stored as a hint; it may be omitted.
`--content` and `--path` are ignored. Missing `--uri` raises
`ValueError: --uri is required when --resource-type uri`.

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
missing `--path` raises `ValueError: --path is required when --resource-type local_file`.

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
- Both endpoints are resolved through the alias map, then parsed as UUIDs. An
  alias that is not in the map is passed straight to `UUID(...)` and fails with
  a `ValueError` about a badly formed hexadecimal UUID string.
- Both endpoints **are** checked for existence at write time. The whole base
  event log is scanned and each endpoint must appear as the `node_id` of some
  event, otherwise the command raises
  `ValueError: SOURCE NODE <uuid> NOT FOUND IN ARCHIVE` or
  `ValueError: TARGET NODE <uuid> NOT FOUND IN ARCHIVE`.
- Because the scan only matches `node_id`, an edge whose source or target is
  itself an **edge** is rejected: edges may only connect nodes.
- The blob for the edge content is written to the blob store *before* the
  endpoints are validated, so a failed `create_edge` can leave an unreferenced
  blob behind. This is harmless — integrity verification ignores unreferenced
  blobs — but it is not cleaned up.
- Edges are directed. Endpoints are immutable: `supersede_edge` may replace an
  edge's content but the index rejects any attempt to change `source_node` or
  `target_node`.
- Prints nothing on success. Use `ik read` to recover the new `e{n}` alias.

```bash
ik create_edge --content "generalises" --source-node e1 --target-node e2
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
- Prints nothing on success.

```bash
ik create_edge_tag --name "conjecture" --description "Unproven claimed relation"
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

- Nothing enforces that an edge tag is applied to an edge, or a node tag to a
  node. The `create_*_tag` distinction is descriptive, not a constraint.
- Re-running `set_tag` with the same pair appends another meta edge; the
  projected tag set is a set, so the result is idempotent in effect but not in
  the log.
- Prints nothing on success.

```bash
ik set_tag --tag m1 --id e3
```
