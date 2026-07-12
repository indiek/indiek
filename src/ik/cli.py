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
import ik.create_edge_tag as create_edge_tag
import ik.create_node_tag as create_node_tag
import ik.set_tag as set_tag
import ik.read as read
import ik.export as export
import ik.ingest as ingest


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
    node_parser = subparsers.add_parser("create_node", help="Create a new node")
    node_parser.add_argument(
        "--content", required=True, help="Text content attached to node"
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
        "ingest", help="Ingest all files in a folder as nodes."
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
    rootp = Path(os.getenv("IK_ARCHIVE_PATH"))  # TODO: use pathlib.Path
    logger.debug(f"{os.getenv("IK_ARCHIVE_PATH")=}")
    infra_blob = InfraBlobStore(archive_root=rootp)
    elog = InfraEventLog(rootp)
    meta_log = InfraEventLog(os.path.join(rootp, "meta"))
    archive = Archive(elog, meta_log, infra_blob)
    archive_index = ArchiveIndex(archive)

    # TODO: for the blob writing events; add a cleaning last step to erase written blob if event persistence failed

    # Route to your scripts based on the command
    if args.command == "create_node":
        create_node.run(
            node_content=args.content,
            curr_public_key=curr_public_key,
            curr_signing_key=curr_signing_key,
            archive_idx=archive_index,
        )

    elif args.command == "create_edge":
        create_edge.run(
            args.content,
            args.source_node,
            args.target_node,
            curr_public_key,
            curr_signing_key,
            archive_index,
        )
    elif args.command == "create_edge_tag":
        create_edge_tag.run(
            tag_name=args.name,
            tag_description=args.description,
            curr_public_key=curr_public_key,
            curr_signing_key=curr_signing_key,
            archive_index=archive_index,
        )
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


if __name__ == "__main__":
    main()
