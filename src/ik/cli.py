import logging
import argparse
from pathlib import Path
import os
import sys
import nacl
from dotenv import load_dotenv
from ik.signing import get_signing_key
from ik.blob import InfraBlobStore, InfraEventLog, Archive, ArchiveIndex
import ik.create_node as create_node
import ik.create_edge as create_edge
import ik.supersede_node as supersede_node
import ik.supersede_edge as supersede_edge
import ik.create_edge_tag as create_edge_tag
import ik.create_node_tag as create_node_tag
import ik.set_tag as set_tag
import ik.read as read
import ik.export as export
import ik.ingest as ingest
import ik.manifest as manifest_mod
import ik.cfg as cfg
from ik.models import MediaType, ResourceType


def parse_comma_separated(value):
    return value.split(",") if value else []


def main():
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler(sys.stdout))
    logger.setLevel(logging.WARNING)  # set to logging.DEBUG if needed
    # CLI ARGS
    parser = argparse.ArgumentParser(
        prog="ik", description="The IndieK CLI application"
    )
    parser.add_argument("--dot-env", required=False, default=".env")
    parser.add_argument("--logging-level", required=False, default="WARNING")
    # Define subparsers for the commands
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Command: $ ik create_node
    cfg_parser = subparsers.add_parser("config", help="Read or set config")
    cfg_parser.add_argument(
        "--set-archive-path",
        required=False,
        help="Path to archive you wish to write to your .env file",
        default=None,
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
        "--content", required=True, help="Replacement text content"
    )

    # Command: $ ik create_edge
    edge_parser = subparsers.add_parser("create_edge", help="Create a new edge")
    edge_parser.add_argument(
        "--content", required=True, help="Text content attached to edge"
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

    edge_tag_parser = subparsers.add_parser(
        "create_edge_tag", help="Create a tag for edges"
    )
    edge_tag_parser.add_argument("--name", required=True, help="Tag Name")
    edge_tag_parser.add_argument("--description", required=True, help="Tag Description")

    node_tag_parser = subparsers.add_parser(
        "create_node_tag", help="Create a tag for nodes"
    )
    node_tag_parser.add_argument("--name", required=True, help="Tag Name")
    node_tag_parser.add_argument("--description", required=True, help="Tag Description")

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

    # Command: $ ik read
    read_parser = subparsers.add_parser("read", help="Read data")
    # breakpoint()
    # read_parser.add_argument()
    read_parser.add_argument(
        "--mini",
        required=False,
        help="Display a lightweight version of the logs.",
        action="store_true",
        default=False,
    )
    # Command: $ ik export
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

    # Command: $ ik manifest
    subparsers.add_parser(
        "manifest",
        help=(
            "Write (or update) MANIFEST.json at the archive root.  "
            "The manifest documents the archive format, schemas, blob store layout, "
            "and registers the current author's public key."
        ),
    )

    # Parse the arguments from the terminal
    args = parser.parse_args()

    try:
        logarg = args.logging_level
    except AttributeError:
        ...
    else:
        logger.setLevel(getattr(logging, logarg))

    # PARSE LOCAL CONFIG (doesn't override system's variables)
    load_dotenv(args.dot_env, override=False)

    # HANDLE KEYS
    # TODO: In a production env distinct authors may trigger distinct OS users -> file permissions
    _private_key_hex: str = os.getenv("IK_AUTHOR_PRIVATE_KEY")

    curr_signing_key: nacl.signing.SigningKey = get_signing_key(_private_key_hex)
    curr_public_key: str = curr_signing_key.verify_key.encode(
        nacl.encoding.HexEncoder
    ).decode("utf-8")

    # SETUP ARCHIVE
    set_arc_path = os.getenv("IK_ARCHIVE_PATH")
    logger.debug(f"{set_arc_path=}")
    rootp = Path(set_arc_path)
    infra_blob = InfraBlobStore(archive_root=rootp)
    elog = InfraEventLog(rootp)
    meta_log = InfraEventLog(os.path.join(rootp, "meta"))
    archive = Archive(elog, meta_log, infra_blob)
    archive_index = ArchiveIndex(archive)

    # TODO: for the blob writing events; add a cleaning last step to erase written blob if event persistence failed

    # Route to your scripts based on the command
    if args.command == "config":
        cfg.run(
            arc_path=set_arc_path,
            set_arc_path=args.set_archive_path,
            dotenv_path=args.dot_env,
        )

    elif args.command == "create_node":
        resource_type = ResourceType(args.resource_type)
        processed_content = None
        inferred_media_type = MediaType(args.media_type) if args.media_type else None
        if resource_type is ResourceType.MANAGED:
            if not args.content:
                parser.error("create_node --content is required for managed nodes")
            processed_content, inferred_media_type = (
                create_node.extract_content_and_mime(args.content)
            )
        node_title = args.title
        if node_title is None and args.content and Path(args.content).is_file():
            node_title = Path(args.content).stem

        node_id = create_node.run(
            node_content=processed_content,
            node_title=node_title,
            curr_public_key=curr_public_key,
            curr_signing_key=curr_signing_key,
            archive_idx=archive_index,
            media_type=inferred_media_type,
            resource_type=resource_type,
            uri=args.uri,
            path=args.path,
        )
        print(f"Node created: {node_id}")

    elif args.command == "supersede_node":
        node_id = supersede_node.run(
            node_id=args.node_id,
            content=args.content,
            title=args.title,
            curr_public_key=curr_public_key,
            curr_signing_key=curr_signing_key,
            archive_idx=archive_index,
        )
        print(f"Node superseded: {node_id}")

    elif args.command == "supersede_edge":
        edge_id = supersede_edge.run(
            edge_id=args.edge_id,
            content=args.content,
            curr_public_key=curr_public_key,
            curr_signing_key=curr_signing_key,
            archive_idx=archive_index,
        )
        print(f"Edge superseded: {edge_id}")

    elif args.command == "create_edge":
        node_id = create_edge.run(
            args.content,
            args.source_node,
            args.target_node,
            curr_public_key,
            curr_signing_key,
            archive_index,
        )
        print(f"Edge created: {node_id}")
    elif args.command == "create_edge_tag":
        node_id = create_edge_tag.run(
            tag_name=args.name,
            tag_description=args.description,
            curr_public_key=curr_public_key,
            curr_signing_key=curr_signing_key,
            archive_index=archive_index,
        )
        print(f"Meta node created: {node_id}")
    elif args.command == "create_node_tag":
        create_node_tag.run(
            tag_name=args.name,
            tag_description=args.description,
            curr_public_key=curr_public_key,
            curr_signing_key=curr_signing_key,
            archive_idx=archive_index,
        )
    elif args.command == "set_tag":
        set_tag.run(
            edge_source=args.tag,
            underlying_target=args.id,
            curr_public_key=curr_public_key,
            curr_signing_key=curr_signing_key,
            archive_idx=archive_index,
        )
    elif args.command == "read":
        read.run(archive_index, args.mini)
    elif args.command == "export":
        export.run(archive_index, args.output_path, args.tags)
    elif args.command == "ingest":
        if args.input_folder:
            file_paths = [
                os.path.join(args.input_folder, fpath)
                for fpath in os.listdir(args.input_folder)
            ]
            file_paths = sorted(file_paths)
            logger.debug(file_paths)
        else:
            file_paths = []

        if args.edges_def_file:
            with open(args.edges_def_file, "rt", encoding="utf-8") as f:
                edge_defs = f.readlines()
        else:
            edge_defs = []

        ingest.run(
            archive_idx=archive_index,
            curr_public_key=curr_public_key,
            curr_signing_key=curr_signing_key,
            file_paths=file_paths,
            edge_definitions=edge_defs,
        )

    elif args.command == "manifest":
        manifest_path = manifest_mod.generate_manifest(
            archive_root=rootp,
            author_public_keys=[curr_public_key],
        )
        print(f"MANIFEST written to: {manifest_path}")


if __name__ == "__main__":
    main()
