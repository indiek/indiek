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

"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import NoReturn

from indiek import (
    Archive,
    Author,
    FsckReport,
    IndieKError,
    MediaType,
    ResourceType,
    VerificationLevel,
)

try:
    from dotenv import dotenv_values, load_dotenv, set_key

    import indiek.read as read
except ModuleNotFoundError as exc:  # pragma: no cover - depends on install extras
    raise SystemExit(
        f"The ik CLI needs optional dependencies ({exc.name} is missing). "
        "Install with: pip install 'indiek[cli]'"
    ) from exc
from indiek.ops.nodes import extract_content_and_mime

logger = logging.getLogger(__name__)

LOGGING_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
ARCHIVE_PATH_VAR = "IK_ARCHIVE_PATH"
PRIVATE_KEY_VAR = "IK_AUTHOR_PRIVATE_KEY"


def parse_comma_separated(value: str) -> list[str]:
    return value.split(",") if value else []


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ik", description="The IndieK CLI application"
    )
    parser.add_argument("--dot-env", required=False, default=".env")
    parser.add_argument(
        "--logging-level",
        type=str.upper,
        choices=LOGGING_LEVELS,
        default="WARNING",
        help="Log level for stderr (case-insensitive, default: WARNING).",
    )
    parser.add_argument(
        "--verify",
        type=str.lower,
        choices=[level.value for level in VerificationLevel],
        default=VerificationLevel.INCREMENTAL.value,
        help=(
            "How much to verify when opening the archive (default: incremental, "
            "which skips only what this machine's cache or --trust-seal vouches "
            "for; 'none' parses only and refuses writes)."
        ),
    )
    parser.add_argument(
        "--trust-seal",
        default=None,
        metavar="HASH",
        help=(
            "A seal hash obtained through a separate, trusted route: the "
            "signatures of the events it covers are not re-checked."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    cfg_parser = subparsers.add_parser("config", help="Read or set config")
    cfg_parser.add_argument(
        "--set-archive-path",
        required=False,
        help="Path to archive you wish to write to your .env file",
        default=None,
    )

    keygen_parser = subparsers.add_parser(
        "keygen",
        help=f"Generate a new Ed25519 author key ({PRIVATE_KEY_VAR}).",
    )
    keygen_parser.add_argument(
        "--write",
        action="store_true",
        help="Store the key in the --dot-env file instead of printing it.",
    )
    keygen_parser.add_argument(
        "--force",
        action="store_true",
        help="With --write, replace a key already present in the --dot-env file.",
    )

    node_parser = subparsers.add_parser("create_node", help="Create a new node")
    node_parser.add_argument(
        "--content",
        required=False,
        help="Content or a supported file path for managed nodes",
    )
    node_parser.add_argument(
        "--title", required=False, default=None, help="Optional title for your node."
    )
    node_parser.add_argument(
        "--resource-type",
        choices=[resource_type.value for resource_type in ResourceType],
        default=ResourceType.MANAGED.value,
        help="Resource storage strategy (default: managed).",
    )
    node_parser.add_argument("--uri", help="External URI for a uri node.")
    node_parser.add_argument("--path", help="Local file path for a local_file node.")
    node_parser.add_argument(
        "--media-type",
        choices=[media_type.value for media_type in MediaType],
        help="Optional media type hint for URI nodes.",
    )

    supersede_node_parser = subparsers.add_parser(
        "supersede_node", help="Append replacement content for an existing node"
    )
    supersede_node_parser.add_argument(
        "--node-id", required=True, help="Node UUID or human-friendly ID"
    )
    supersede_node_parser.add_argument(
        "--content", required=True, help="Replacement Markdown content"
    )
    supersede_node_parser.add_argument(
        "--title", help="Replacement title (keeps existing title when omitted)"
    )

    supersede_edge_parser = subparsers.add_parser(
        "supersede_edge", help="Append replacement content for an existing edge"
    )
    supersede_edge_parser.add_argument(
        "--edge-id", required=True, help="Edge UUID or human-friendly ID"
    )
    supersede_edge_parser.add_argument(
        "--content", help="Replacement text content (omit for an edge without content)"
    )

    edge_parser = subparsers.add_parser("create_edge", help="Create a new edge")
    edge_parser.add_argument(
        "--content", help="Text content attached to edge (omit for none)"
    )
    edge_parser.add_argument(
        "--source-node",
        required=True,
        help="ID of source node (possibly human-friendly)",
    )
    edge_parser.add_argument(
        "--target-node",
        required=True,
        help="ID of target node (possibly human-friendly)",
    )

    for kind in ("edge", "node"):
        tag_kind_parser = subparsers.add_parser(
            f"create_{kind}_tag", help=f"Create a tag for {kind}s"
        )
        tag_kind_parser.add_argument("--name", required=True, help="Tag Name")
        tag_kind_parser.add_argument(
            "--description", required=True, help="Tag Description"
        )

    tag_parser = subparsers.add_parser("set_tag", help="Set a tag for an edge or node")
    tag_parser.add_argument(
        "--tag",
        required=True,
        help="Tag ID (possibly human friendly ID). This is the source node for the edge in the meta network",
    )
    tag_parser.add_argument(
        "--id",
        required=True,
        help="ID of edge or node to tag (possibly human friendly). This is the target node for the edge in the meta network.",
    )

    read_parser = subparsers.add_parser("read", help="Read data")
    read_parser.add_argument(
        "--mini",
        required=False,
        help="Display a lightweight version of the logs.",
        action="store_true",
        default=False,
    )

    export_parser = subparsers.add_parser(
        "export", help="Export the full archive to a GraphML file"
    )
    export_parser.add_argument(
        "--output-path", required=True, help="Path to file to be persisted to disk"
    )
    export_parser.add_argument(
        "--tags",
        required=False,
        help="Comma-separated list of tags to apply filter",
        type=parse_comma_separated,
        default=[],
    )

    ingest_parser = subparsers.add_parser(
        "ingest",
        help="""Ingest all files in a folder as nodes. Combine
        with ik --logging-level CRITICAL to render the logger
          less verbose at stdout.""",
    )
    ingest_parser.add_argument(
        "--input-folder",
        required=False,
        default=None,
        help="Folder to be browsed for nodes ingestion from text files.",
    )
    ingest_parser.add_argument(
        "--edges-def-file",
        required=False,
        default=None,
        help="File defining edges to create.",
    )

    subparsers.add_parser(
        "seal",
        help=(
            "Append a signed seal of both logs and the blob store; prints the "
            "seal hash, the one string that commits to the whole archive."
        ),
    )
    subparsers.add_parser(
        "fsck",
        help="Fully verify the archive and print a report (counts, heads, "
        "seals, unreferenced blobs).",
    )
    verify_parser = subparsers.add_parser(
        "verify", help="Fully re-verify the archive, its seals and its blob set."
    )
    verify_parser.add_argument(
        "--expect",
        default=None,
        metavar="HASH",
        help="Fail unless this seal hash is in the seal log.",
    )

    transcribe_parser = subparsers.add_parser(
        "transcribe",
        help=(
            "Attest the verified base (or meta) log: append a signed "
            "transcription event recording its head and length."
        ),
    )
    transcribe_parser.add_argument(
        "--network",
        choices=["base", "meta"],
        default="base",
        help="Log to attest; the event is appended to that same log (default: base).",
    )
    transcribe_parser.add_argument(
        "--note", default=None, help="Optional free-text note stored in the event."
    )

    subparsers.add_parser(
        "manifest",
        help=(
            "Write (or update) MANIFEST.json at the archive root.  "
            "The manifest documents the archive format, schemas, blob store layout, "
            "and registers the current author's public key."
        ),
    )
    return parser


def _create_node(
    ik: Archive, args: argparse.Namespace, parser: argparse.ArgumentParser
) -> None:
    resource_type = ResourceType(args.resource_type)
    media_type = MediaType(args.media_type) if args.media_type else None
    title = args.title
    if resource_type is ResourceType.MANAGED:
        if not args.content:
            parser.error("create_node --content is required for managed nodes")
        # Known limitation: detection overrides --media-type for managed nodes.
        content, media_type = extract_content_and_mime(args.content)
    if title is None and args.content and Path(args.content).is_file():
        title = Path(args.content).stem

    if resource_type is ResourceType.URI:
        if not args.uri:
            parser.error("--uri is required when --resource-type uri")
        node_id = ik.create_node(
            resource_type=resource_type,
            uri=args.uri,
            title=title,
            media_type=media_type,
        )
    elif resource_type is ResourceType.LOCAL_FILE:
        if not args.path:
            parser.error("--path is required when --resource-type local_file")
        node_id = ik.create_node(
            resource_type=resource_type, path=args.path, title=title
        )
    else:
        node_id = ik.create_node(content, media_type=media_type, title=title)
    print(f"Node created: {node_id}")


def _configure_logging(level: str) -> None:
    """Send every log record to stderr, keeping stdout for command output."""
    root_logger = logging.getLogger()
    root_logger.addHandler(logging.StreamHandler(sys.stderr))
    root_logger.setLevel(level)


def _keygen(args: argparse.Namespace) -> None:
    author = Author.generate()
    if not args.write:
        print(f"{PRIVATE_KEY_VAR}={author.seed_hex}")
        print(f"Public key: {author.public_key_hex}", file=sys.stderr)
        return
    dotenv_path = Path(args.dot_env)
    if dotenv_values(dotenv_path).get(PRIVATE_KEY_VAR) and not args.force:
        print(
            f"{dotenv_path} already defines {PRIVATE_KEY_VAR}; "
            "pass --force to replace it (the old key is lost).",
            file=sys.stderr,
        )
        sys.exit(1)
    set_key(dotenv_path, PRIVATE_KEY_VAR, author.seed_hex)
    dotenv_path.chmod(0o600)
    print(f"{PRIVATE_KEY_VAR} written to {dotenv_path}", file=sys.stderr)
    print(f"Public key: {author.public_key_hex}", file=sys.stderr)


def _config(args: argparse.Namespace, archive_path: str | None) -> None:
    if archive_path:
        print(f"{ARCHIVE_PATH_VAR}={archive_path}")
    else:
        print(f"{ARCHIVE_PATH_VAR} is not set")
    if args.set_archive_path:
        set_key(args.dot_env, ARCHIVE_PATH_VAR, args.set_archive_path)
        print(f"{ARCHIVE_PATH_VAR}={args.set_archive_path}")


def _verify(ik: Archive, expect: str | None) -> None:
    found = ik.verify(expect=expect)
    store = ik.index.store
    print(
        f"Archive verified: {store.base.count} base events, "
        f"{store.meta.count} meta events, {store.seals.count} seals"
    )
    latest = store.seals.latest
    if expect is not None and found is not None:
        print(f"Expected seal found: seal {found.seq} of {store.seals.count}")
    if latest is not None:
        print(f"Latest seal: {latest.hash}")


def _print_fsck(report: FsckReport) -> None:
    latest = report.latest_seal
    lines = [
        f"Archive: {report.path}",
        f"Base log: {report.base_count} events, head {report.base_head}",
        f"Meta log: {report.meta_count} events, head {report.meta_head}",
        f"Seals: {report.seal_count}"
        + (f", latest seal {latest.seq}: {latest.hash}" if latest else ""),
        "Transcriptions: "
        + ", ".join(f"{n} {c}" for n, c in report.transcriptions.items()),
        f"Blobs: {report.blob_files} files, {report.referenced_blobs} referenced, "
        f"{len(report.unreferenced_blobs)} unreferenced",
        *(f"  unreferenced (safe to delete): {p}" for p in report.unreferenced_blobs),
        f"Representations without a tag: {report.untagged_representations}",
        "Verification: full, OK",
    ]
    print("\n".join(lines))


def _fail(message: str) -> NoReturn:
    """Report a failed command on one stderr line and exit 1 (traceback at DEBUG)."""
    logger.debug("ik failed", exc_info=True)
    print(f"ik: error: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    _configure_logging(args.logging_level)

    # Local config never overrides real environment variables.
    load_dotenv(args.dot_env, override=False)
    archive_path = os.getenv(ARCHIVE_PATH_VAR)

    # Bootstrap commands: no archive, no key.
    if args.command == "keygen":
        _keygen(args)
        return
    if args.command == "config":
        _config(args, archive_path)
        return

    if not archive_path:
        parser.error(f"{ARCHIVE_PATH_VAR} is not set (environment or --dot-env file)")
    try:
        _run_archive_command(args, parser, archive_path)
    except IndieKError as exc:
        _fail(str(exc))


def _run_archive_command(
    args: argparse.Namespace, parser: argparse.ArgumentParser, archive_path: str
) -> None:
    seed_hex = os.getenv(PRIVATE_KEY_VAR)
    try:
        author = Author.from_seed_hex(seed_hex) if seed_hex else None  # None: read-only
    except ValueError as exc:  # never echo the key itself
        _fail(f"{PRIVATE_KEY_VAR} is invalid: {exc}")
    logger.debug("archive_path=%s", archive_path)
    ik = Archive.open(
        archive_path,
        author=author,
        verify=args.verify,
        trusted_seal=args.trust_seal,
    )

    match args.command:
        case "create_node":
            _create_node(ik, args, parser)
        case "supersede_node":
            node_id = ik.supersede_node(args.node_id, args.content, title=args.title)
            print(f"Node superseded: {node_id}")
        case "supersede_edge":
            edge_id = ik.supersede_edge(args.edge_id, args.content)
            print(f"Edge superseded: {edge_id}")
        case "create_edge":
            edge_id = ik.create_edge(args.source_node, args.target_node, args.content)
            print(f"Edge created: {edge_id}")
        case "create_edge_tag":
            tag_id = ik.create_tag(args.name, args.description, kind="edge")
            print(f"Meta node created: {tag_id}")
        case "create_node_tag":
            ik.create_tag(args.name, args.description, kind="node")
        case "set_tag":
            ik.set_tag(args.tag, args.id)
        case "read":
            read.run(ik, args.mini)
        case "export":
            ik.export_graphml(args.output_path, args.tags)
        case "ingest":
            ik.ingest(input_folder=args.input_folder, edges_file=args.edges_def_file)
        case "seal":
            new_seal = ik.seal()
            print(f"Seal {new_seal.seq} created: {new_seal.hash}")
        case "verify":
            _verify(ik, args.expect)
        case "fsck":
            _print_fsck(ik.fsck())
        case "transcribe":
            new_head = ik.transcribe(args.network, note=args.note)
            print(f"Transcription appended: {new_head}")
        case "manifest":
            print(f"MANIFEST written to: {ik.write_manifest()}")


if __name__ == "__main__":
    main()
