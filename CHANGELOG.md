# Changelog

All notable changes to the `indiek` package (the `ik` CLI) are documented here.

## [Unreleased]

### Added
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

### Changed
- Formatted and linted `src/indiek` and `tests` with `ruff` (formatting only, no behaviour change).
- `README.md` corrected where it disagreed with the source.
- `README.md`: documented `create_node_tag`; replaced the claim that tag kind is descriptive with the enforced rule (edge tags only on edges, node tags only on nodes) and its two error messages; noted that a rejected first-time `set_tag` still appends the representation event, documented as intended and accompanied by a logged warning.

### Fixed
- README: `create_node_tag` prints nothing; all logging goes to stdout; `--logging-level` must be uppercase; invalid `--media-type` exits 2; file-stem title fallback applies to every resource type; `ik config` cannot bootstrap without `IK_ARCHIVE_PATH`.
- `test_set_tag.py`: node-tagging tests now create node tags (`_make_tag(kind=...)`) instead of edge tags, matching the constraint in `create_meta_edge`; edge test uses the full `--source-node`/`--target-node` flags. Added `test_tag_kind_must_match_target_kind` for both mismatch directions. Suite: 56 passed.
