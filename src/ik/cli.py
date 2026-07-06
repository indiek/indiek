import argparse
import os
import nacl
from dotenv import load_dotenv
from ik.signing import get_signing_key
from ik.blob import InfraBlobStore, InfraEventLog, Archive
import ik.create_node as create_node


def main():

    # CLI ARGS
    parser = argparse.ArgumentParser(
        prog="ik", description="The IndieK CLI application"
    )

    # Define subparsers for the commands
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Command: $ ik create_node
    node_parser = subparsers.add_parser("create_node", help="Create a new node")
    node_parser.add_argument("--author", required=True, help="Author standard name")
    node_parser.add_argument(
        "--content", required=True, help="Text content attached to node"
    )

    # Command: $ ik create_edge
    edge_parser = subparsers.add_parser("create_edge", help="Create a new edge")
    edge_parser.add_argument("--author", required=True, help="Author standard name")
    edge_parser.add_argument(
        "--content", required=True, help="Text content attached to edge"
    )
    edge_parser.add_argument("--source-node", required=True, help="ID of source node")
    edge_parser.add_argument("--target-node", required=True, help="ID of target node")

    # Command: $ ik read
    # read_parser = subparsers.add_parser("read", help="Read data")

    # Parse the arguments from the terminal
    args = parser.parse_args()

    # PARSE LOCAL CONFIG
    load_dotenv()

    # HANDLE KEYS
    my_private_key_hex: str = os.getenv("GENESIS_AUTHOR_PRIVATE_KEY")
    anonymous_1_private_hex: str = os.getenv("ANONYMOUS1_PRIVATE_KEY")
    anonymous_1_signing_key: nacl.signing.SigningKey = get_signing_key(
        anonymous_1_private_hex
    )
    signing_key: nacl.signing.SigningKey = get_signing_key(my_private_key_hex)
    public_key_hex: str = signing_key.verify_key.encode(
        nacl.encoding.HexEncoder
    ).decode("utf-8")
    anonymous1_public_key_hex: str = anonymous_1_signing_key.verify_key.encode(
        nacl.encoding.HexEncoder
    ).decode("utf-8")
    print("GENESIS AUTHOR PUBLIC KEY HEX (author_id) IS:", public_key_hex)
    print(
        "ANONYMOUS AUTHOR 1 PUBLIC KEY HEX (author_id) IS:", anonymous1_public_key_hex
    )

    # SETUP ARCHIVE
    rootp = "/Users/adrianradillo/prog/indiek/public_archive/archive/"
    infra_blob = InfraBlobStore(archive_root=rootp)
    elog = InfraEventLog(rootp)
    archive = Archive(elog, infra_blob)
    print(f"THE ARCHIVE AT {rootp} HAS {archive.nevents_} EVENTS")

    if args.command in {"create_node", "create_edge"}:
        if args.author == "ANONYMOUS1":
            curr_signing_key = anonymous_1_signing_key
            curr_public_key = anonymous1_public_key_hex
        elif args.author == "GENESIS":
            curr_signing_key = signing_key
            curr_public_key = public_key_hex
        else:
            raise ValueError(f"Unknown author {args.author}")

    # Route to your scripts based on the command
    if args.command == "create_node":
        create_node.run(args.content, curr_public_key, curr_signing_key, archive)

    elif args.command == "create_edge":
        # create_edge.run()
        pass
    elif args.command == "read":
        # read.run()
        pass


if __name__ == "__main__":
    main()
