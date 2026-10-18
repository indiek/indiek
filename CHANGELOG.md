# Changelog

All notable changes to the `indiek` package are documented here.

## Unreleased

## 0.16.0 - 2026-10-17

### Added
- (VERIFY-LEVELS-CACHE) `indiek.VerificationLevel` (`NONE`, `INCREMENTAL`, `FULL`; owner decision D13, the plan's `HEAD_ONLY` dropped since building the index reads every line anyway). `Archive.open(path, author=None, *, verify="incremental", trusted_seal=None, cache_dir=None)`, `Archive.verification`, `Archive.refresh(level=None)`.
- (VERIFY-LEVELS-CACHE) Trust model (owner decisions 2026-10-17): verification work is skipped only on the basis of (a) the local cache of what this machine already verified, or (b) a seal hash the reader supplies (`trusted_seal`, `--trust-seal HASH`), never (c) a seal merely found in the archive. Every hash link, anchor, transcription and seal is always recomputed; only Ed25519 checks (and, via the cache, blob re-hashing) are skipped; any mismatch falls back to a full pass with the same error a `FULL` check reports.
- (VERIFY-LEVELS-CACHE) `indiek.core.cache`: the cache lives OUTSIDE the archive in the user's cache directory (`~/Library/Caches/indiek`, `$XDG_CACHE_HOME/indiek` or `~/.cache/indiek`, `%LOCALAPPDATA%\indiek\Cache`; override `IK_CACHE_DIR`), one `state.json` per archive holding verified chain tips and blob `(size, mtime_ns)` (D14, D15). Written atomically, ignored when corrupt.
- (VERIFY-LEVELS-CACHE) `Archive.fsck() -> indiek.FsckReport` and `ik fsck` (counts, heads, seals, transcriptions, blob census with deletable unreferenced paths, representations without a tag). CLI global flags `--verify {none,incremental,full}` and `--trust-seal HASH`.
- (VERIFY-LEVELS-CACHE) `BlobStore.stat()`, `core.archive.BlobChecker`, `scan_chain()`, `verify_chain(..., trusted=, checker=)`.
- (VERIFY-LEVELS-CACHE) README: "Verification levels and the trust model" (levels with measured timings, what may be skipped and why, the Alice/Mallory example, cache location, caveats, verify-on-read), `ik fsck` section, new flags and `IK_CACHE_DIR`.
- (VERIFY-LEVELS-CACHE) Tests: `tests/sdk/test_verify_levels.py` (cache location, skipping counted by signature checks, stale/corrupt/planted caches, bit rot caught on read, trusted seal, a seal in the archive never trusted, `NONE`, forced `FULL`, `fsck`) + 4 CLI tests; autouse fixture isolating `IK_CACHE_DIR` per test; pytest marker `slow` (10,000-event test, `uv run pytest -m slow`). Suite: 368 passed (+1 slow).

### Breaking
- (VERIFY-LEVELS-CACHE) The SDK and CLI default is now `INCREMENTAL` (was: everything on every open). `verify()`, `fsck()`, `seal()`, `ingest()`, `export_graphml()`, `write_manifest()` and their CLI commands always verify `FULL` first. An archive opened with `verify="none"` refuses writes (`ArchiveRuleError`).
- (VERIFY-LEVELS-CACHE) `BlobStore.get()` / `get_text()` verify on read (D16): a missing or altered blob raises `IntegrityError("File corrupted or missing! (blob …)")` (a missing blob used to raise `FileNotFoundError`).
- (VERIFY-LEVELS-CACHE) `ArchiveStore(…, *, level=FULL, trusted_seal=None, cache_dir=None)` / `ArchiveStore.open(root, *, …)`; `reopen(level=None)`. The core still reads no environment variable (the facade resolves the cache directory).

### Changed
- (VERIFY-LEVELS-CACHE) The INFO log line is now `ARCHIVE INTEGRITY VERIFIED (<level>)`.

## 0.15.0 - 2026-10-17

### Added
- (SEAL-LOG) Seal log `seals/seals.ndjson` (seal.md B): each line is a signed checkpoint `{type: "seal", version, seq, prev_seal_hash, base: {head, count}, meta: {head, count}, blob_root, time, hash_alg, sig_alg, key, sig}`. `sig` = `ed25519:<hex>` over the canonical bytes minus `sig`; seal hash = `sha256:<hex>` of the whole seal, the one string committing to the archive.
- (SEAL-LOG) `blob_root` = RFC 6962 Merkle Tree Hash (SHA-256; leaf `0x00 || raw 32-byte digest`, node `0x01 || left || right`, empty = `SHA-256("")`) over the sorted blobs **referenced by the events the seal covers** (owner decision 2026-10-17, option C). New `indiek.core.merkle.blob_root`.
- (SEAL-LOG) `Archive.seal() -> indiek.Seal`, `Archive.seals()`, `Archive.verify(expect=None)` (raises `IntegrityError("Expected seal not found in seal log")`), `Archive.unreferenced_blobs()`; `ik seal` (prints `Seal <n> created: <hash>`) and `ik verify [--expect HASH]` (prints counts and the latest seal).
- (SEAL-LOG) `indiek.core.seals` (`Seal`, `SealChain`, `verify_seals`), `indiek.core.storage.SealLog`, `indiek.core.models.SealModel` / `LogTip`, `indiek.core.signing.sign_object` / `verify_object` (events now use them), `ChainState.blobs`, `ArchiveStore.seals` / `referenced_blobs` / `unreferenced_blobs`, `indiek.ops.seal`.
- (SEAL-LOG) MANIFEST `seal_log` section (signing, chain, tips, exact `blob_root` rule, unreferenced-blob policy) and `Seal` / `LogTip` schemas. Test vectors: `merkle_vectors` (0, 1, 2, 3, 5 leaves), `seal_vectors`, rules `blob_root` and `seal`.
- (SEAL-LOG) README: "Seals and the blob store" section, `ik seal` and `ik verify` sections, walkthrough ends with `ik seal` / `ik verify`.
- (SEAL-LOG) Tests: `tests/sdk/test_merkle.py` (24, against an independent RFC 6962 reference), `tests/sdk/test_seal_log.py` (31), 6 CLI seal/verify tests. Suite: 333 passed.

### Breaking
- (SEAL-LOG) Opening an archive also verifies every seal: `IntegrityError("Seal chain broken!")` (link, `seq`, signature or shape), `("Seal does not match logs!")` (tip absent from the verified logs, e.g. a rewritten or truncated log or a missing `meta/`), `("Seal goes back in log history")` (owner decision D10: counts never decrease), `("Blob set does not match seal!")`, plus the `Unsupported algorithm` / `Algorithm mismatch` checks shared with events.
- (SEAL-LOG) `seal()` / `ik seal` refuse (`ArchiveRuleError`) an empty archive, an archive unchanged since the latest seal (owner decision D11; any key may seal), and an archive holding unreferenced blobs (option C; the error lists the files to delete).

### Changed
- (SEAL-LOG) Unreferenced blobs (files under `blobs/sha256/` no event references) are now reported with a WARNING on every open; they never fail verification. Seals of an empty archive and repeated seals only WARN on read (owner decision D11b).
- (SEAL-LOG) `tests/cli/test_golden_archive.py` ends with `ik seal` and pins the seal hash; base head, meta head and blob set unchanged.

## 0.14.0 - 2026-10-17

### Breaking
- (META-ANCHORS) Meta commits to base, base never commits to meta (seal.md A). Every meta event header now requires `base_seq` (number of base events the author had verified) and `base_head` (hash of base event number `base_seq`; `null` exactly when `base_seq` is 0). Meta logs written by 0.13.0 no longer open.
- (META-ANCHORS) Verification checks every meta anchor against the verified base: `IntegrityError("Meta anchor does not match base history")` when the base has fewer than `base_seq` events or event `base_seq` hashes to something else (catches a rewritten or truncated base that still verifies on its own); `IntegrityError("Meta anchor goes back in base history")` when `base_seq` decreases along the meta log (owner decision D7, to revisit with multi-writer collaboration).

### Added
- (META-ANCHORS) `indiek.core.models.MetaEventHeader` is its own class (was an alias of `EventHeader`) with an anchor-consistency validator; `append_meta` fills the anchor from the verified store, so SDK and CLI writes need no change.
- (META-ANCHORS) `verify_chain(log, blobs, anchors=None)`; `ChainState.hashes` (per-event hashes, excluded from equality); `ArchiveStore` verifies base first, then meta against the base hashes.
- (META-ANCHORS) `MANIFEST.json`: `MetaEventHeader` schema (referenced by `MetaEventModel`) and `event_log.meta_anchors` rule.
- (META-ANCHORS) Tests: `tests/sdk/test_meta_anchors.py` (14); `tests/sdk/_builders.py` tracks base hashes and can craft anchors. Suite: 272 passed.

### Changed
- (META-ANCHORS) `src/indiek/spec/test_vectors.json` regenerated: the meta vector anchors to base vector 2; new rule `meta_anchor`.
- (META-ANCHORS) `tests/cli/test_golden_archive.py` meta head re-recorded (base head and blob set unchanged).

## 0.13.0 - 2026-10-17

### Breaking
- (FORMAT3-ALG-AGILITY) Format 3.0 events now name their algorithms: `header.hash_alg` (`"sha256"`) and `header.sig_alg` (`"ed25519"`) are required. Digests and signatures are prefixed strings: `prev_hash` is `sha256:<hex>`, `signature` is `ed25519:<hex>` (blob hashes keep `sha256:<hex>`). Archives written by 0.12.0 no longer open (no backward compatibility before the first public release).
- (FORMAT3-ALG-AGILITY) `Archive.head`, `Archive.meta_head`, `ArchiveIndex.head`/`meta_head`, `ChainState.head` and `indiek.core.canonical.event_hash()` return prefixed digests (`sha256:<hex>`); `sign_event()` returns `ed25519:<hex>`.
- (FORMAT3-ALG-AGILITY) New verification errors: `IntegrityError("Unsupported algorithm …")` for an unknown or missing `hash_alg`/`sig_alg`; `IntegrityError("Algorithm mismatch …")` when the `signature` or a non-null `prev_hash` does not carry the header's algorithm as prefix (bare hex included); `IntegrityError("Transcription does not match chain")` for a false attestation.
- (SUPERSEDE-AUTHORSHIP) Only the original author of a node or edge may supersede it (owner decision 2026-10-17; others who disagree create their own node + edge). `supersede_node` / `supersede_edge` (SDK, ops and CLI) raise `AuthorshipError("Only the author of <Node|Edge> '<ref>' may supersede it")` before any blob is written, and index replay rejects a log containing a supersede signed by another key with `IntegrityError("Supersede by a non-author of item <id>")`. `IndexedItem.author` is therefore always the creator.

### Added
- (FORMAT3-ALG-AGILITY) `transcription` events, allowed in the base AND the meta log, each attesting only its own log: body `verified_head`, `verified_count`, `verified_hash_alg`, `verified_sig_alg`, `verified_at`, optional `note`. Verification checks that `verified_head` is the hash of event number `verified_count` of that log, earlier than the transcription. No alias is allocated and no projection changes. Any author may transcribe; an empty log cannot be transcribed (`ArchiveRuleError`).
- (FORMAT3-ALG-AGILITY) `Archive.transcribe(network="base", *, note=None)` (returns the new head), `indiek.ops.transcription.transcribe`, `ik transcribe [--network base|meta] [--note TEXT]` (prints `Transcription appended: <hash>`), `ArchiveIndex.transcriptions["base"|"meta"]` of `indiek.TranscriptionRecord(author, position, body)`.
- (FORMAT3-ALG-AGILITY) `indiek.core.canonical`: `parse_digest()`, `parse_signature()`, `digest()`, `algorithm_of()`, registries `HASH_ALGORITHMS` / `SIGNATURE_ALGORITHMS`, `DEFAULT_HASH_ALG` / `DEFAULT_SIG_ALG`; `indiek.core.models.Transcription`, `DigestStr`, `EventType.TRANSCRIPTION` / `MetaEventType.TRANSCRIPTION`; `ChainState.sig_alg`.
- (FORMAT3-ALG-AGILITY) `MANIFEST.json` gains `algorithms: {hash: [...], signature: [...]}` (every algorithm appearing in the archive, via `indiek.ops.manifest.collect_algorithms`), a `TranscriptionBody` schema, `hash_alg`/`sig_alg` header fields and an `event_log.algorithm_agility` rule.
- (FORMAT3-ALG-AGILITY) Tests: `tests/sdk/test_alg_agility.py` (35) and 5 `ik transcribe` CLI tests.
- (SUPERSEDE-AUTHORSHIP) Tests: `tests/sdk/test_supersede_authorship.py` (7), a replay test in `tests/sdk/test_index.py`, a CLI refusal test (node + edge) in `tests/cli/test_readme_claims.py`; the two tests that pinned "any key may supersede" now pin the author-only rule. README supersede sections updated. Suite: 258 passed.

### Changed
- (FORMAT3-ALG-AGILITY) `src/indiek/spec/test_vectors.json` regenerated: prefixed values, vector keys renamed `signature_hex` → `signature` and `event_hash_hex` → `event_hash`, new rules `algorithms` and `transcription`, and a fourth vector (a base transcription by a second author).
- (FORMAT3-ALG-AGILITY) `tests/cli/test_golden_archive.py` head constants re-recorded (now prefixed); blob set unchanged.

## 0.12.0 - 2026-10-17

### Breaking
- (FORMAT3-CANONICAL) Archive format **3.0** is the only format read or written. Events whose `header.version` is not `"3.0"` raise `IntegrityError("Unsupported format version …")`, so 1.0/2.0 archives no longer open. Owner decision: no backward compatibility (and no migration tool) before the first public release; compatibility is guaranteed from that release on.

### Changed
- (FORMAT3-CANONICAL) Canonical bytes are now compact: `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` encoded as UTF-8 (was default separators with `\uXXXX` escapes).
- (FORMAT3-CANONICAL) Signatures cover the **whole event** minus its `signature` field (`{header, body}`), Ed25519 over the canonical bytes with no SHA-256 pre-hash (was: the SHA-256 digest of the body only). This closes a replay attack where an author's old signed body could be re-appended under a forged header (new `prev_hash`/timestamp) and still verify in their name.
- (FORMAT3-CANONICAL) Event hash (`prev_hash` of the next event, archive head) = SHA-256 hex of the canonical bytes of the whole event, signature included.
- (FORMAT3-CANONICAL) Log lines are parsed strictly: duplicate keys, floats, `NaN`/`Infinity`, malformed JSON or a non-object line raise `IntegrityError`.
- (FORMAT3-CANONICAL) Only the first event of a log may, and must, have `prev_hash: null`; a log whose first events were deleted now fails with `Chain broken!` (it used to verify).
- (FORMAT3-CANONICAL) `MANIFEST.json` wording states the exact 3.0 rules (the old "compact JSON" text was wrong for 2.0) and adds `event_log.canonical_bytes`, `event_log.strict_parsing` and `signature_algorithm.specification` (RFC 8032).
- (FORMAT3-CANONICAL) `tests/cli/test_golden_archive.py` head constants re-recorded for 3.0 (blob set unchanged).

### Added
- (FORMAT3-CANONICAL) `src/indiek/spec/test_vectors.json`: three deterministic vectors (event, signing bytes, signature, event hash, fixed public test seeds) plus the rules in prose; regenerate with `uv run python scripts/make_test_vectors.py`.
- (FORMAT3-CANONICAL) `indiek.core.canonical.event_hash`, `parse_line`, `json_ready`; `indiek.core.signing.signing_bytes`, `sign_event`, `verify_event`. Tests: `tests/sdk/test_canonical_signing.py` rewritten (28 tests, incl. the replay scenario and prefix truncation). Suite: 208 passed.

### Removed
- (FORMAT3-CANONICAL) `indiek.core.canonical.canonical_hash`, `indiek.core.signing.sign_body` / `verify_body` (replaced by `event_hash`, `sign_event`, `verify_event`).

## 0.11.0 - 2026-10-16 

### Added
- (SDK-REORG-CLI-THIN) `ik keygen [--write] [--force]`: prints a dotenv-ready `IK_AUTHOR_PRIVATE_KEY=<seed>` line (public key on stderr), or with `--write` stores it in the `--dot-env` file (mode `600`), refusing to replace an existing key without `--force`.
- (SDK-REORG-CLI-THIN) `tests/test_cli_thin.py` (19 tests: stderr logging, level case-folding, `config`/`keygen` bootstrap, read-only commands without a key) and `tests/sdk/test_import_footprint.py` (`import indiek` loads neither `rich` nor `dotenv`).
- (SDK-REORG-CLI-THIN) README: Install section, `ik keygen` section, "which commands need what" in Environment.
- (SDK-REORG-LAYOUT) `indiek.core`: `models` (moved unchanged), `canonical` (format 2.0 canonical bytes + SHA-256), `signing` (`sign_body` / `verify_body`), `storage` (`EventLog`, `BlobStore`), `archive` (`verify_chain`, `ChainState`, `ArchiveStore`), `index` (`ArchiveIndex` with a single `resolve(id_or_alias)`, typed `IndexedItem` / `ItemKind`), `author` (`Author.from_seed_hex()` / `generate()`), `errors`.
- (SDK-REORG-LAYOUT) `indiek.ops`: `events` (`append_base` / `append_meta`), `nodes`, `edges`, `tags`, `ingest` (`IngestResult`), `export` (`export_graphml`), `manifest` (`write_manifest`). Every op takes `(index, author, ...)`, returns UUIDs and never prints.
- (SDK-REORG-LAYOUT) `indiek.Archive` facade (`Archive.open(path, author=None)`): `create_node`, `create_edge`, `supersede_node`, `supersede_edge`, `create_tag(kind=...)`, `set_tag`, `ingest`, `export_graphml`, `write_manifest`, `events()`, `index`, `head`, `meta_head`, `refresh()`. The index refreshes after every write. `Archive.create_node` never treats `content` as a file path (path detection is CLI-only). `indiek/__init__.py` re-exports the facade, `Author`, enums, errors and `__version__` with `__all__`.
- (SDK-REORG-LAYOUT) Error hierarchy: `IndieKError` > `IntegrityError`, `UnknownItemError`, `AuthorshipError`, `ArchiveRuleError` (the last three are also `ValueError`, so existing `except ValueError` callers keep working). Messages are unchanged.
- (SDK-REORG-LAYOUT) `tests/sdk/` (140 tests, no CLI, no dotenv; `_builders.py` writes signed events with `core` only) and `tests/test_golden_archive.py`, which freezes UUIDv7s/timestamps/seed and pins the base/meta head hashes and blob set of a fixed scenario recorded on 0.10.0: archives written after the reorg are byte-identical. Suite: 198 passed.
- README now documents all 12 `ik` subcommands (`config`, `supersede_node`, `supersede_edge`, `read`, `export`, `ingest`, `manifest` added), with a command index, an Environment section and a from-scratch walkthrough exercising every command.
- `tests/test_readme_claims.py` (10 tests) verifying the new README claims and the walkthrough's alias numbering.
- pytest suite under `tests/` covering the commands documented in the README:
  - `conftest.py`: hermetic fixtures (throwaway archive in `tmp_path`, ephemeral Ed25519 authors, in-process `run_cli`, NDJSON/blob readers).
  - `test_create_node.py`, `test_create_edge.py`, `test_create_edge_tag.py`, `test_set_tag.py`: per-command behaviour and error paths.
  - `test_cli_global.py`: `--dot-env`, `--logging-level`, and the three integrity errors (`Data tampered or bad author!`, `Chain broken!`, `File corrupted or missing!`).
  - `test_signing_units.py`: key loading, canonical hashing (default JSON separators), sign/verify round-trip.
- `set_tag`: when a first-time `set_tag` is rejected (tag kind ≠ target kind) after writing the target's representation, a `WARNING` naming the representation and target UUIDs is logged before the `ValueError` is re-raised. The leftover representation is intended behaviour.
- Tests for that warning in `test_set_tag.py` (`caplog` assertions in `test_tag_kind_must_match_target_kind`, new `test_no_warning_when_rejected_target_already_has_representation`). Suite: 57 passed.
- `[tool.pytest.ini_options]` in `pyproject.toml` (`testpaths = ["tests"]`, `pythonpath = ["src"]`).

- (SDK-REORG-TESTS-LEAN) `tests/cli/test_cli_commands.py`: CLI-only behaviour of the archive subcommands (usage errors, flag validation, printed ids, CLI-side defaults); `tests/cli/conftest.py` holds `run_cli`.
- (SDK-REORG-TESTS-LEAN) `README.md` section "Errors and exit codes".

### Changed
- (SDK-REORG-CLI-THIN) All logging goes to **stderr** (was stdout); stdout carries only command output.
- (SDK-REORG-CLI-THIN) `ik config` prints `IK_ARCHIVE_PATH=<value>` / `IK_ARCHIVE_PATH is not set` on stdout instead of logging at WARNING, and needs neither a key nor an archive.
- (SDK-REORG-CLI-THIN) `read`, `export` and `manifest` work without `IK_AUTHOR_PRIVATE_KEY` (read-only open; `manifest` then lists no author); writes without a key raise `AuthorshipError`. A missing `IK_ARCHIVE_PATH` is a usage error (exit 2) instead of a `TypeError`.
- (SDK-REORG-CLI-THIN) Packaging: core dependencies are only `pynacl` + `pydantic`; `rich` and `python-dotenv` moved to the `indiek[cli]` extra (the `ik` script exits with an install hint when they are missing), `networkx` + `pyvis` to the `viz` extra (for `scripts/viz.py`). The `dev` group depends on `indiek[cli]`. `description` updated.
- (SDK-REORG-LAYOUT) `ik` is now a thin layer over `indiek.Archive` (`build_parser()` + one facade call per subcommand); flags, printed output and exit codes are unchanged. `read.py` takes an `Archive`.
- (SDK-REORG-LAYOUT) `ARCHIVE INTEGRITY VERIFIED` is logged at INFO instead of WARNING, so it no longer appears on stdout at the default level.
- (SDK-REORG-LAYOUT) `~` in `IK_ARCHIVE_PATH` is expanded (it used to create a directory literally named `~`).
- (SDK-REORG-LAYOUT) Unknown aliases raise `UnknownItemError("Unknown ID or alias '<ref>'")` instead of a bare `KeyError` (`export --tags`) or a "badly formed hexadecimal UUID string" `ValueError`.
- (SDK-REORG-LAYOUT) The duplicate-blob notice (`***WARNING*** FILE EXISTS…`) is now a DEBUG message.
- Formatted and linted `src/indiek` and `tests` with `ruff` (formatting only, no behaviour change).
- `README.md` corrected where it disagreed with the source.
- `README.md`: documented `create_node_tag`; replaced the claim that tag kind is descriptive with the enforced rule (edge tags only on edges, node tags only on nodes) and its two error messages; noted that a rejected first-time `set_tag` still appends the representation event, documented as intended and accompanied by a logged warning.

- (SDK-REORG-TESTS-LEAN) **CLI errors:** a failed command prints one line `ik: error: <message>` on stderr and exits 1, without traceback (`--logging-level DEBUG` logs it). Catches every `IndieKError`. Missing `--uri` / `--path` are now argparse usage errors (exit 2). A malformed `IK_AUTHOR_PRIVATE_KEY` exits 1 with `IK_AUTHOR_PRIVATE_KEY is invalid: <reason>`, never echoing the key.
- (SDK-REORG-TESTS-LEAN) Tests split into `tests/sdk/` and `tests/cli/`; the root `conftest.py` no longer imports `indiek.cli`, so SDK tests never load `dotenv`/`rich`. All tests formatted with `ruff format`. Suite: 218 → 192 tests (duplicates removed, no coverage lost).

### Fixed
- (SDK-REORG-CLI-THIN) `--logging-level` is case-insensitive and validated with argparse `choices` (lowercase names used to crash with `TypeError`, unknown ones with `AttributeError`).
- (SDK-REORG-CLI-THIN) `ik config` can bootstrap a fresh setup (it used to crash with `TypeError` when `IK_ARCHIVE_PATH` was unset). `test_readme_claims.py`: the two tests that pinned these bugs now pin the fixed behaviour. Suite: 218 passed.
- (SDK-REORG-LAYOUT) A missing blob now raises `IntegrityError("File corrupted or missing!")` as documented, instead of a raw `FileNotFoundError`.
- (SDK-REORG-LAYOUT) `create_edge` validates both endpoints before writing the content blob: a failed call no longer leaves an unreferenced blob.
- (SDK-REORG-LAYOUT) `set_tag` with an unknown tag UUID raises `UnknownItemError` instead of crashing with `KeyError`.
- README: `create_node_tag` prints nothing; all logging goes to stdout; `--logging-level` must be uppercase; invalid `--media-type` exits 2; file-stem title fallback applies to every resource type; `ik config` cannot bootstrap without `IK_ARCHIVE_PATH`.
- `test_set_tag.py`: node-tagging tests now create node tags (`_make_tag(kind=...)`) instead of edge tags, matching the constraint in `create_meta_edge`; edge test uses the full `--source-node`/`--target-node` flags. Added `test_tag_kind_must_match_target_kind` for both mismatch directions. Suite: 56 passed.

### Removed
- (SDK-REORG-LAYOUT) **Breaking for direct importers:** the flat modules `indiek.{blob, cfg, create_edge, create_edge_tag, create_node, create_node_tag, events, export, ingest, manifest, models, set_tag, signing, supersede_edge, supersede_node}`. Use `indiek` / `indiek.core` / `indiek.ops`. `fastAPI/` still imports them and is broken until DESKTOP:FASTAPI-MIGRATE-TO-SDK.
- (SDK-REORG-LAYOUT) `tests/test_signing_units.py`, superseded by `tests/sdk/test_canonical_signing.py` and `tests/sdk/test_errors_author.py`.

- (SDK-REORG-TESTS-LEAN) `tests/test_create_node.py`, `test_create_edge.py`, `test_create_edge_tag.py`, `test_set_tag.py`: assertions not already in `tests/sdk/` were ported there (raw `body_type`, `underlying_id` fields) or to `tests/cli/test_cli_commands.py`.
- (SDK-REORG-TESTS-LEAN) Repo clutter: `lib/`, `graphml_exports/`, `sandbox/`, `tmparchive.zip`, and the stray `CHANGELOG` file (its 0.9.0/0.10.0 history is merged below).

## 0.10.0 - 2026-10-16
### Added
- unit tests
- Apache 2.0 license

## 0.9.0 - 2026-08-27
### Added
- Initial release.
