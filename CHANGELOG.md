# Changelog

All notable changes to the `indiek` package are documented here.

## Unreleased

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
