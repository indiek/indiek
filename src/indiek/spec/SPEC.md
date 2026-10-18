# IndieK archive format — specification, format version 3.0

This document is the normative specification of the IndieK archive format,
format version `3.0`. It is shipped inside the `indiek` Python package and,
by `ik manifest`, at the root of every archive, next to `MANIFEST.json` and
`test_vectors.json`. It contains everything needed to read, verify and write
an archive without any IndieK software.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be
interpreted as described in RFC 2119.

## 1. Overview

An IndieK archive stores a knowledge graph — nodes, directed edges between
nodes, and tags on both — as a folder of plain files:

- two **append-only event logs**, one JSON object per line: the **base log**
  (the knowledge graph itself) and the **meta log** (tags and tag
  assignments, which annotate the base);
- a **content-addressed blob store** holding the content of nodes and edges
  (text, images, PDF/A), each file named after its SHA-256 digest;
- an optional **seal log** of signed checkpoints, each committing to both logs
  and to the blobs they reference.

Every event is signed with Ed25519 by its author and linked to the previous
event of its log by a hash, so that any change to the history is detectable.
Nothing is ever edited in place: a revision is a new *supersede* event; the
earlier record stays in the log.

Design goals, in order: the archive must remain verifiable for centuries
(plain text, standard primitives, no dependency on any software, version
control system or service); a single flipped bit must damage as little as
possible and always be detected; the spec must be reimplementable from this
document in a day.

The event logs and the blobs are the only source of truth. Aliases, indexes,
caches and every other derived view MUST be rebuildable from them.

## 2. Notation

- *hex* means lowercase hexadecimal (`0-9a-f`).
- A *digest* is written `<hash_alg>:<hex>`, e.g. `sha256:9f86…`.
- A *signature* is written `<sig_alg>:<hex>`, e.g. `ed25519:b88a…`.
- `SHA-256(x)` is the 32-byte FIPS 180-4 digest of the bytes `x`;
  `||` is byte concatenation.
- *Event number n* is the n-th event of a log, counting from 1 (§3.2).
- `canonical(v)` is the canonical byte string of the JSON value `v` (§4).

## 3. Archive layout and encoding

### 3.1 Archive root

| Entry | Content | Required |
| --- | --- | --- |
| `events/` | Base event log (§6, §7) | for a non-empty archive |
| `meta/events/` | Meta event log (§6, §8) | no |
| `blobs/` | Blob store, `blobs/sha256/…` (§10) | as soon as an event references a blob |
| `seals/` | Seal log, `seals/seals.ndjson` (§12) | no |
| `MANIFEST.json` | Machine-readable layout and JSON Schemas (§17) | no, informative |
| `SPEC.md` | This document (§17) | no, informative |
| `test_vectors.json` | Test vectors (§18) | no, informative |

Readers MUST ignore any other entry. In particular, a verification cache is
never part of an archive (§16): a `.ik-cache/` folder, or any other file a
reader might find, MUST NOT influence verification.

An archive without `meta/` is valid on its own: base events never mention
the meta log (§11). An archive without `seals/` is valid too. A seal commits
to both logs, so `seals/` MUST NOT be kept without `meta/` when the seals
cover meta events (§12).

### 3.2 Log files and event order

A log is stored as NDJSON files under its root (`events/` or `meta/events/`).
Writers append each event, as one line terminated by LF (`0x0A`), to
`<log root>/YYYY/MM/DD/events.ndjson`, where the date is the UTC date of the
event's `header.timestamp`.

To read a log, a reader MUST take every regular file under the log root whose
name ends in `ndjson`, sort them by their path relative to the log root
(lexicographic string order), and read each file top to bottom. The
resulting sequence is the log; its first event is *event number 1*. The
timestamps play no role in ordering.

A writer MUST NOT append an event to a file that sorts before the file
holding the current last event (for example after the system clock moved
back across midnight): the read order would no longer match the chain and the
log would be invalid (`Chain broken!`).

### 3.3 Strict parsing of lines

Every line of every log (event logs and seal log) MUST be:

1. valid UTF-8 — otherwise `Invalid log line: not UTF-8`;
2. exactly one JSON value (RFC 8259) that is an object — otherwise
   `Invalid log line: not a JSON object`, or `Invalid log line: <JSON error>`
   for malformed JSON, including empty lines;
3. free of duplicate keys in every object — otherwise
   `Invalid log line: duplicate JSON key`;
4. free of non-integer numbers: no fraction, no exponent, no `NaN`,
   `Infinity` or `-Infinity` — otherwise
   `Invalid log line: non-integer number …`;
5. free of integers outside [−(2^53−1), 2^53−1] = [−9007199254740991,
   9007199254740991] — otherwise `Invalid log line: integer … is outside ±(2^53−1)`;
6. free of strings containing a lone surrogate (e.g. the escape `"\ud800"`
   not followed by a low surrogate): such a string is not a sequence of
   Unicode scalar values and has no canonical form — otherwise
   `Invalid string: lone surrogate (not a Unicode scalar value)`.

A line that violates any rule makes the archive invalid. Whitespace between
JSON tokens, including a trailing CR, is allowed and irrelevant: hashes and
signatures are computed over canonical bytes of the parsed value (§4), never
over the bytes on disk. Writers SHOULD write compact lines.

## 4. Canonical bytes

Hashes and signatures are computed over **canonical bytes**. The canonical
form is **RFC 8785 (JSON Canonicalization Scheme, JCS) restricted to**:

- object keys made of ASCII characters only, and
- numbers that are integers in [−(2^53−1), 2^53−1].

Every key defined by this format is ASCII, and §3.3 rejects every other
number, so every valid line has a canonical form. Within this subset the
canonical bytes are:

- no whitespace anywhere;
- object members sorted by key, comparing keys character by character (for
  ASCII keys, byte order); nested objects sorted recursively; array order
  kept;
- `true`, `false`, `null` as such; integers in decimal, no leading zeros, `-`
  for negatives, `0` for zero;
- strings in double quotes, with `"` → `\"`, `\` → `\\`, U+0008 → `\b`,
  U+0009 → `\t`, U+000A → `\n`, U+000C → `\f`, U+000D → `\r`, every other
  character below U+0020 → `\u00xx` (lowercase hex); every other character,
  ASCII or not, written as itself;
- the whole string encoded as UTF-8.

In Python, for values in this subset, this is exactly
`json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`.

The restriction is deliberate: full RFC 8785 sorts non-ASCII keys by UTF-16
code units and serialises every number as an IEEE-754 double. A future
format version that needs non-ASCII keys, fractions or larger integers MUST
either adopt full RFC 8785 or define the extension explicitly.

Writers MUST NOT produce a value outside the subset (the reference
implementation refuses with `ArchiveRuleError`).

Worked example — the canonical bytes of the unsigned event of
`test_vectors.json` vector 1 (one line):

```
{"body":{"blob_hash":"sha256:71a0b54b349d9f8a95d6bb621386c3cb939b0a711dbf4e746e3031c38b4104f5","body_type":"node","event_type":"create_node","file_hash":null,"file_size":null,"last_verified":null,"media_type":"text/plain; charset=utf-8","node_id":"019a0000-0000-7000-8000-000000000001","path":null,"resource_type":"managed","title":"Gödel — incompleteness","uri":null},"header":{"author":"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c","hash_alg":"sha256","prev_hash":null,"sig_alg":"ed25519","timestamp":"2026-10-17T12:00:00Z","version":"3.0"}}
```

## 5. Algorithms

Every hash and signature names its algorithm, so the format can outlive the
algorithms it starts with (algorithm agility).

| Kind | Name | Definition | Encoding |
| --- | --- | --- | --- |
| hash | `sha256` | SHA-256 (FIPS 180-4) | `sha256:` + 64 hex |
| signature | `ed25519` | PureEd25519 (RFC 8032), 32-byte public key | `ed25519:` + 128 hex |

These are the only algorithms of format 3.0. A reader MUST reject an event
or seal naming any other algorithm (`Unsupported algorithm …`).

Public keys (`header.author`, seal `key`) are the 32-byte Ed25519 public key
as 64 hex characters, without prefix. A signing identity is a 32-byte Ed25519
seed; it is never stored in an archive.

Blob digests (§10) are always `sha256:`; they do not follow `hash_alg`.

## 6. Events

### 6.1 Structure

Every line of an event log is an **event**:

```json
{"header": {…}, "body": {…}, "signature": "ed25519:<128 hex>"}
```

### 6.2 Header (base and meta)

| Field | Type | Rule |
| --- | --- | --- |
| `version` | string | MUST be `"3.0"`, else `Unsupported format version …` |
| `hash_alg` | string | MUST be a supported hash algorithm (§5) |
| `sig_alg` | string | MUST be a supported signature algorithm (§5) |
| `prev_hash` | digest or `null` | chain link (§6.5) |
| `timestamp` | string | RFC 3339 date-time with time zone, time of writing (e.g. `2026-10-17T12:00:00Z`) |
| `author` | string | 64-hex Ed25519 public key of the signer |

### 6.3 Meta header

Meta events carry two more header fields, the **anchor** (§11):

| Field | Type | Rule |
| --- | --- | --- |
| `base_seq` | integer ≥ 0 | number of base events the author had verified |
| `base_head` | digest or `null` | hash of base event number `base_seq`; `null` exactly when `base_seq` is 0 |

### 6.4 Signature

`signature` = `<sig_alg>:<hex>` of the Ed25519 signature, by the key in
`header.author`, of `canonical(event without its "signature" member)` — that
is, of `{"body": …, "header": …}`. The bytes are signed directly (no
pre-hash). Because the header is signed, a signature is bound to its position
in the chain, its time and its author: a signed event cannot be replayed
elsewhere.

The prefix of `signature` MUST equal `header.sig_alg`; a missing or different
prefix is `Algorithm mismatch …`. A signature that does not verify is
`Data tampered or bad author!`.

### 6.5 Event hash and chain

The **hash of an event** under algorithm `a` is `a:` + hex of
`a(canonical(whole event, signature included))`.

- The first event of a log MUST have `prev_hash: null`, and no other event
  may.
- Every other event's `prev_hash` MUST equal the hash of the preceding event,
  computed with the `hash_alg` of the event that holds the `prev_hash`; its
  prefix MUST equal that `hash_alg` (`Algorithm mismatch …`).
- Any violation is `Chain broken!`. Removing the first events of a log is
  therefore detected.

The hash of the last event of a log is its **head**, under that event's own
`hash_alg`. Two copies of a log are identical if and only if their heads
are. Event hashes, under each event's own `hash_alg`, are what anchors (§11),
transcriptions (§9) and seals (§12) refer to.

## 7. Base network

### 7.1 Body types

The base body is discriminated by `body_type`:

| `body_type` | `event_type` | Identifier fields | Meaning |
| --- | --- | --- | --- |
| `node` | `create_node` | `node_id` | create a node |
| `edge` | `create_edge` | `edge_id`, `source_node`, `target_node` | create a directed edge from `source_node` to `target_node` |
| `supersede_node` | `supersede_node` | `node_id` | replace the content of node `node_id` |
| `supersede_edge` | `supersede_edge` | `edge_id`, `source_node`, `target_node` | replace the content of edge `edge_id`; endpoints MUST be unchanged |
| `transcription` | `transcription` | — | attestation, §9 |

Identifiers are UUID strings (writers use UUIDv7, RFC 9562, lowercase,
hyphenated). A node or edge keeps its identifier across supersedes.

### 7.2 Resource fields

Every node, edge and supersede body carries the resource fields below.
Writers emit every field, with `null` when unused.

| Field | Type | Meaning |
| --- | --- | --- |
| `resource_type` | `"managed"`, `"uri"`, `"local_file"` | where the content lives |
| `media_type` | media type or `null` | one of the archival media types (§7.3) |
| `blob_hash` | `sha256:<64 hex>` or `null` | content in the blob store |
| `uri` | string or `null` | external reference, never fetched |
| `path` | string or `null` | path of a file on the writer's machine |
| `file_size` | integer ≥ 0 or `null` | its size in bytes |
| `file_hash` | `sha256:<64 hex>` or `null` | its SHA-256 |
| `last_verified` | RFC 3339 date-time or `null` | when size and hash were taken |
| `title` | string or `null` | human-readable title |

Rules per resource type:

- `managed`: `blob_hash` and `media_type` REQUIRED; `uri`, `path`,
  `file_size`, `file_hash`, `last_verified` MUST be `null`. The referenced
  blob MUST exist and match (§10).
- `uri`: `uri` REQUIRED; `blob_hash` and the four local-file fields MUST be
  `null`; `media_type` is an optional hint.
- `local_file`: `path`, `file_size`, `file_hash`, `last_verified` and
  `media_type` REQUIRED; `blob_hash` and `uri` MUST be `null`. The file is
  not part of the archive; its fingerprint lets a reader detect that it
  changed. `file_hash` is not checked against the blob store.

### 7.3 Archival media types

`text/plain; charset=utf-8`, `text/markdown; charset=utf-8`, `image/tiff`,
`image/png`, `image/jpeg`, `application/pdf; profile=pdfa`.

## 8. Meta network

The meta network encodes tags as a graph of its own, so that anyone can
annotate a base network without touching it.

| `body_type` | `event_type` | Fields | Meaning |
| --- | --- | --- | --- |
| `tag` | `create_node_tag` or `create_edge_tag` | `node_id`, `name`, `description` | define a tag for nodes, or for edges |
| `representation` | `create_node_representation` or `create_edge_representation` | `node_id`, `underlying_id` | a meta node standing for base node or edge `underlying_id` |
| `edge` | `set_node_tag` or `set_edge_tag` | `edge_id`, `source_node`, `target_node` | assign tag `source_node` to the item represented by `target_node` |
| `transcription` | `transcription` | — | attestation, §9 |

Tag names are free text and not unique. Tagging a base item therefore takes
up to two meta events: a representation of the item (once per item) and a
meta edge from the tag to that representation.

## 9. Transcriptions

A **transcription** event says: "I verified this log up to event number
`verified_count`, whose hash is `verified_head`, under `verified_hash_alg` /
`verified_sig_alg`, at `verified_at`." Signed under current algorithms, it lets
a chain of custody outlive the algorithms it started with: future authors
re-attest old history with new primitives.

Body: `body_type` and `event_type` both `"transcription"`, `verified_head`
(digest), `verified_count` (integer ≥ 1), `verified_hash_alg`,
`verified_sig_alg` (strings), `verified_at` (RFC 3339 date-time), `note`
(string or `null`).

A transcription MAY appear in the base log or in the meta log and attests
only the log it sits in. It is valid only if `verified_count` is at least 1
and smaller than its own event number, `verified_head` equals the hash of
event number `verified_count` of the same log, and the prefix of
`verified_head` equals `verified_hash_alg`; otherwise
`Transcription does not match chain`. Any author may transcribe. A
transcription creates no item and allocates no alias.

## 10. Blob store

A blob's name is the hex SHA-256 of its bytes; it is stored at
`blobs/sha256/<hex[0:2]>/<hex[2:4]>/<hex>`. Events reference it as
`blob_hash: "sha256:<hex>"`. Blobs are immutable and deduplicated: identical
content is stored once.

For every event with a non-null `blob_hash` — in either log — the file MUST
exist and its bytes MUST hash to its name; otherwise the archive is invalid:
`File corrupted or missing!`. Text blobs are UTF-8.

A file under `blobs/sha256/` that no event references is **unreferenced**
(typically the leftover of an interrupted write, or a file added by hand). It
is not part of the knowledge graph and does not make the archive invalid;
readers SHOULD warn about it (§15).

## 11. Meta anchors

**Meta commits to base; base never commits to meta.** Every meta event
records, in `base_seq` / `base_head`, the tip of the base log its author had
verified when writing it. Readers verify the base log first, then check each
meta event in order:

- `base_seq` MUST be between 0 and the number of base events, and
  `base_head` MUST equal the hash of base event number `base_seq` (`null` for
  0); otherwise `Meta anchor does not match base history`. A base log that was
  rewritten or truncated after annotations were made therefore invalidates
  them, even though it still verifies on its own;
- `base_seq` MUST NOT decrease along the meta log; otherwise
  `Meta anchor goes back in base history`.

Base events have no anchor fields. The base can be shipped and verified
without the meta log, and anyone can annotate a base with their own key.

## 12. Seal log

### 12.1 Seals

`seals/seals.ndjson` is an append-only log of **seals**, one per line, parsed
with the rules of §3.3. A seal is a signed checkpoint of the whole archive:

| Field | Type | Rule |
| --- | --- | --- |
| `type` | `"seal"` | |
| `version` | `"3.0"` | else `Unsupported format version …` |
| `seq` | integer ≥ 1 | MUST equal the seal's position in the log, from 1 |
| `prev_seal_hash` | digest or `null` | hash of the previous seal; `null` for the first seal and only there |
| `base` | `{"head", "count"}` | tip of the base log: `head` = hash of base event number `count`, `null` exactly when `count` is 0 |
| `meta` | `{"head", "count"}` | tip of the meta log, same rule |
| `blob_root` | `sha256:<hex>` | Merkle root of the blobs the sealed events reference (§12.2) |
| `time` | RFC 3339 date-time | time of sealing |
| `hash_alg`, `sig_alg` | strings | supported algorithms (§5) |
| `key` | 64 hex | Ed25519 public key of the sealer |
| `sig` | `<sig_alg>:<hex>` | signature by `key` of `canonical(seal without "sig")` |

The **seal hash** is `hash_alg:` + hex of `hash_alg(canonical(whole seal))`;
`prev_seal_hash` is computed with the `hash_alg` of the seal holding it, and
the prefixes of `prev_seal_hash` and `sig` MUST equal the seal's algorithms
(`Algorithm mismatch …`). The hash of the latest seal is one short string
that commits to the entire archive at that moment; publishing it lets anyone
check a copy (§16). Any key may seal.

### 12.2 `blob_root`

`blob_root` is the RFC 6962 Merkle Tree Hash, with SHA-256, over the set `S`
of distinct blob digests referenced by `blob_hash` in base events 1…`base.count`
and meta events 1…`meta.count`, sorted in ascending hex order:

- each leaf is `SHA-256(0x00 || d)`, where `d` is the raw 32-byte digest;
- each inner node is `SHA-256(0x01 || left || right)`;
- leaves are paired level by level, left to right; an odd last node is
  promoted unchanged to the next level (this yields exactly RFC 6962's tree);
- the root of an empty set is `SHA-256("")`;
- the result is written `sha256:<hex>`.

### 12.3 Seal verification

Seals are checked after both logs, in order; for each seal:

1. `type` is `"seal"`, `seq` equals its position, `prev_seal_hash` links to
   the previous seal, `sig` verifies, and every field has the type above —
   otherwise `Seal chain broken!` (`Unsupported format version …`,
   `Unsupported algorithm …` and `Algorithm mismatch …` as for events);
2. both tips exist, with those hashes, in the verified logs — otherwise
   `Seal does not match logs!` (a log rewritten or truncated after the seal,
   or `meta/` missing);
3. neither count is lower than in the previous seal — otherwise
   `Seal goes back in log history`;
4. `blob_root` equals the root recomputed per §12.2 — otherwise
   `Blob set does not match seal!`.

Every seal is checked, not only the latest. Events appended after a seal do
not affect it: a seal only speaks about the events up to its counts.

A seal cannot prove that it is the latest one. Freshness always needs an
outside reference: a seal hash published somewhere the reader trusts.

## 13. Verification procedure

An archive is **valid** when all of the following hold:

1. Every line of the base log, the meta log and the seal log obeys §3.3.
2. The base log, read in order (§3.2), obeys for each event: version (§6.2),
   algorithms and prefixes (§5, §6.4, §6.5), chain link (§6.5), signature
   (§6.4), referenced blob (§10), transcription (§9).
3. The meta log obeys the same rules plus the anchor rules (§11).
4. The seal log obeys §12.3.
5. Replaying both logs obeys the projection rules (§14).

The reference implementation checks the base log, then the meta log, then
the seal log, then replays; within a log it reads line by line (parsing
included) and runs each event's checks in the order of item 2, the anchor
coming right after the signature for meta events. It reports the first
failure. An archive with several
defects may legitimately be reported with a different message by another
implementation; the normative part is validity.

## 14. Projection (replay) rules

Readers build the current state of the graph by replaying the logs in order.

**Aliases.** In the base log, each `create_node` or `create_edge` takes the
next alias `e1`, `e2`, … (one counter for nodes and edges). In the meta log,
each tag, representation and tag assignment takes the next alias `m1`, `m2`,
…. Supersedes and transcriptions take none. Aliases are a convenience of the
projection, not part of the format: they are never written in events.

**Supersedes.** A `supersede_node` / `supersede_edge` replaces the projected
body of an existing item, which keeps its identifier and alias. On replay:

- the item MUST exist: `Supersede event references unknown item <id>`;
- the supersede type MUST match the item (node vs edge):
  `Supersede event type does not match item <id>`;
- it MUST be signed by the item's creator (the author of its create event):
  `Supersede by a non-author of item <id>`;
- a `supersede_edge` MUST keep `source_node` and `target_node`:
  `Supersede edge events cannot change endpoints`.

**Tags.** A tag assignment's `target_node` MUST be a representation created
earlier in the meta log, whose `underlying_id` is an item created earlier
in the archive (writers only ever represent base nodes and edges); otherwise
`Tag assignment references an unknown representation`. The assigned tags of a
base item form a set: repeating an assignment changes nothing.

All projection failures are integrity errors: the archive is invalid.

## 15. Writer rules and warnings

These rules bind writers. Readers do not check them, so an archive written by
other software that breaks them stays valid.

- Edge endpoints (`source_node`, `target_node`) are existing base nodes,
  never edges or meta items.
- Only a tag's author assigns it, and a node tag goes on a node, an edge tag
  on an edge.
- At most one representation is created per base item.
- A meta event is anchored to the base tip the writer has just verified.
- A blob is written before the event that references it. A crash in between
  leaves an unreferenced blob, never a dangling reference.
- A seal is refused for an empty archive, for an archive unchanged since the
  latest seal, and while unreferenced blobs exist (they would be outside
  every seal).

Readers SHOULD report, without failing:

- unreferenced blobs (§10);
- a seal of an empty archive, or a seal that repeats the tips and
  `blob_root` of the previous seal;
- `SPEC.md` or `test_vectors.json` at the archive root that differ from the
  reader's own copies (§17).

## 16. Verification in practice (informative)

Checking every signature and re-hashing every blob on every open does not
scale to large archives. A reader MAY skip some checks, but only on two
grounds:

- **its own record of what it verified before**, kept outside the archive in
  the user's cache directory: "the signatures of events 1…N were valid and
  event N hashed to H". The reader still recomputes every hash link; if event
  N still hashes to H, events 1…N are the same bytes and their signatures
  need not be checked again. Blob files whose size and modification time
  are unchanged need not be re-hashed;
- **a seal hash obtained through a separate, trusted route** (the author's
  website, a printed page): the seal with that hash MUST be in the seal log —
  otherwise `Expected seal not found in seal log` — and the recomputed
  chains MUST reach its tips; the signatures of the events it covers need not
  be re-checked.

A reader MUST NOT skip any check because of a seal it merely found in the
archive: any key may seal, so such a seal proves nothing about who checked
what. Seals found in an archive are always checked, never trusted.

The reference implementation offers three levels: `none` (parse only;
read-only), `incremental` (the default: skip only on the two grounds above)
and `full` (check everything). Reading a blob always re-hashes it
(`File corrupted or missing! (blob <hex>)`).

## 17. Informative files

`ik manifest` writes three files at the archive root:

- `MANIFEST.json`: format name and version, the algorithms used in the
  archive, layout, rules, and JSON Schemas (draft 2020-12) of every log line,
  generated from the reference implementation's models. `log_lines` maps
  `events/`, `meta/events/` and `seals/` to their schema. It holds no event
  data. Its `authors` list is informative.
- `SPEC.md`: this document.
- `test_vectors.json`: §18.

None of them affects validity: they may be absent, and a reader finding them
different from its own copies SHOULD only warn (they were probably written by
another version of the software). This document never names a software
version, so it changes only when the format or its wording does.

## 18. Test vectors

`test_vectors.json` lets an independent implementation prove itself. Its
`rules` restate this specification in one line each. It contains:

- `vectors`: events. For each, derive the Ed25519 key pair from `seed_hex`
  (it MUST give `public_key_hex`); check that
  `canonical(event_unsigned)` is `signing_bytes_hex`; sign it — Ed25519 is
  deterministic, so the result MUST be `signature`; adding it to
  `event_unsigned` MUST give `event`; the hash of `event` MUST be
  `event_hash`. The vectors form a base log (genesis, a chained edge, a
  transcription) and a meta log anchored to it, with non-ASCII strings.
- `merkle_vectors`: `blob_root` of 0, 1, 2, 3 and 5 leaves.
- `seal_vectors`: a seal of those logs, checked like an event
  (`seal_unsigned`, `signing_bytes_hex`, `sig`, `seal`, `seal_hash`).

The seeds are public test values; never use them as real keys.

## 19. Error messages

Messages of the reference implementation (`IntegrityError`), for
cross-implementation reports. `…` stands for details.

| Message | Section |
| --- | --- |
| `Invalid log line: not UTF-8` | §3.3 |
| `Invalid log line: not a JSON object` / `Invalid log line: <JSON error>` | §3.3 |
| `Invalid log line: duplicate JSON key` | §3.3 |
| `Invalid log line: non-integer number …` | §3.3 |
| `Invalid log line: integer … is outside ±(2^53−1)` | §3.3 |
| `Invalid string: lone surrogate (not a Unicode scalar value)` | §3.3 |
| `Unsupported format version …` | §6.2, §12.1 |
| `Unsupported algorithm …` | §5 |
| `Algorithm mismatch: <field> uses '<alg>' prefix, header says '<alg>'` (seals: `seal says`) | §6.4, §6.5, §12.1 |
| `Chain broken!` | §6.5 |
| `Data tampered or bad author!` | §6.4 |
| `File corrupted or missing!` | §10 |
| `Meta anchor does not match base history` | §11 |
| `Meta anchor goes back in base history` | §11 |
| `Transcription does not match chain` | §9 |
| `Seal chain broken!` | §12.3 |
| `Seal does not match logs!` | §12.3 |
| `Seal goes back in log history` | §12.3 |
| `Blob set does not match seal!` | §12.3 |
| `Expected seal not found in seal log` | §16 |
| `Supersede event references unknown item <id>` | §14 |
| `Supersede event type does not match item <id>` | §14 |
| `Supersede by a non-author of item <id>` | §14 |
| `Supersede edge events cannot change endpoints` | §14 |
| `Tag assignment references an unknown representation` | §14 |

## 20. Conformance of the reference implementation

The `indiek` Python package implements this specification, with one known
gap: on read it checks the fields that verification and replay use, but it
does not yet validate every event against the schemas of §6–§9 (for example
the per-resource-type field rules of §7.2, or the absence of unknown
members). Such events are rejected when the reference implementation writes
them, and an independent reader SHOULD reject them.

## 21. Versioning

This document specifies format `3.0`, the first public version of the
format. Every event and seal carries its format version; readers MUST reject
versions they do not implement. Future versions will keep every archive
written in a published version readable.
