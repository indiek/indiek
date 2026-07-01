import os
from dotenv import load_dotenv
from signing import get_signing_key, verify_signature
from blob import InfraBlobStore, InfraEventLog, Archive
from events import create_node, create_event, write_event, MediaType, EventModel
import nacl
from pprint import pprint

load_dotenv()

# Retrieve the key
my_private_key_hex: str = os.getenv("GENESIS_AUTHOR_PRIVATE_KEY")
anonymous_1_private_hex: str = os.getenv("ANONYMOUS1_PRIVATE_KEY")
anonymous_1_signing_key: nacl.signing.SigningKey = get_signing_key(
    anonymous_1_private_hex
)
signing_key: nacl.signing.SigningKey = get_signing_key(my_private_key_hex)
public_key_hex: str = signing_key.verify_key.encode(nacl.encoding.HexEncoder).decode(
    "utf-8"
)
anonymous1_public_key_hex: str = signing_key.verify_key.encode(
    nacl.encoding.HexEncoder
).decode("utf-8")
print("GENESIS AUTHOR PUBLIC KEY HEX (author_id) IS:", public_key_hex)
print("ANONYMOUS AUTHOR 1 PUBLIC KEY HEX (author_id) IS:", anonymous1_public_key_hex)
if __name__ == "__main__":
    import sys
    import json

    rootp = "/Users/adrianradillo/prog/indiek/public_archive/archive/"
    infra_blob = InfraBlobStore(archive_root=rootp)
    elog = InfraEventLog(rootp)
    archive = Archive(elog, infra_blob)
    print(f"THE ARCHIVE AT {rootp} HAS {archive.nevents_} EVENTS")
    if sys.argv[1] == "createtextnode":

        node_content = sys.argv[2]
        author_arg = sys.argv[3]
        if author_arg == "ANONYMOUS1":
            curr_signing_key = anonymous_1_signing_key
            curr_public_key = anonymous1_public_key_hex
        else:
            curr_signing_key = signing_key
            curr_public_key = public_key_hex
        media_type = MediaType.TEXT_PLAIN

        binary_content: bytes = archive.blob_store.bin_encode_decode(
            content=node_content, content_type=media_type, encode_decode="encode"
        )

        # The hash is the ID and determines the storage path
        blob_hash: str = archive.blob_store.get_blob_hash(
            binary_content
        )  # sha256:XXXXX

        archive.blob_store.persist_bin_blob(binary_content, blob_hash)

        body = create_node(
            blob_hash=blob_hash,
            data_type="text/plain; charset=utf-8",
            blob_hash_prefix=archive.blob_store.blob_hash_prefix,
        )

        event = create_event(payload=body, public_key=curr_public_key, archive=archive)

        write_event([event], signing_key, archive.event_log)
    # elif sys.argv[1] == "createedge":

    #     edge_content = "Some metadata text associated with this edge"
    #     media_type = "text/plain; charset=utf-8"

    #     binary_content: bytes = infra.bin_encode_decode(
    #         content=edge_content, content_type=media_type, encode_decode="encode"
    #     )

    #     # The hash is the ID and determines the storage path
    #     blob_hash: str = infra.get_blob_hash(binary_content)  # sha256:XXXXX

    #     infra.persist_bin_blob(binary_content, blob_hash)

    #     json_dict = create_edge(
    #         source_node_id=None,
    #         target_node_id=None,
    #         blob_hash=blob_hash,
    #         data_type="text/plain; charset=utf-8",
    #         blob_hash_prefix=infra.blob_hash_prefix,
    #     )

    #     event = create_event(
    #         payload=json_dict,
    #         prev_hash="auto",
    #         public_key=public_key_hex,
    #         first_event=False,
    #     )

    #     write_event(event, signing_key, infra.root_path)
    elif sys.argv[1] == "read":
        for event_dict in archive.event_log:
            pprint(event_dict)
            event = EventModel(**event_dict)
            binary_data = archive.blob_store.load_bin_blob(event.body.blob_hash)
            decoded_data = archive.blob_store.bin_encode_decode(
                binary_data, event.body.media_type, "decode"
            )
            print("DECODED DATA", decoded_data)
            print("")
