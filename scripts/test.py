import os
from dotenv import load_dotenv
from signing import get_signing_key, verify_event
from blob import InfraBlobStore
from events import create_node, create_event, write_events
import nacl

load_dotenv()

# Retrieve the key
my_private_key_hex: str = os.getenv("GENESIS_AUTHOR_PRIVATE_KEY")
signing_key: nacl.signing.SigningKey = get_signing_key(my_private_key_hex)
public_key_hex: str = signing_key.verify_key.encode(nacl.encoding.HexEncoder).decode(
    "utf-8"
)
if __name__ == "__main__":
    import sys
    import json

    infra = InfraBlobStore(
        archive_root="/Users/adrianradillo/prog/indiek/public_archive/archive/"
    )
    if sys.argv[1] == "create":

        node1_content = "Ohm"
        media_type = "text/plain; charset=utf-8"

        binary_content: bytes = infra.bin_encode_decode(
            content=node1_content, content_type=media_type, encode_decode="encode"
        )

        # The hash is the ID and determines the storage path
        blob_hash: str = infra.get_blob_hash(binary_content)  # sha256:XXXXX

        infra.persist_bin_blob(binary_content, blob_hash)

        json_dict = create_node(
            blob_hash=blob_hash, data_type="text/plain; charset=utf-8"
        )

        event = create_event(
            payload=json_dict, prev_hash=None, public_key=public_key_hex
        )

        write_events([event], signing_key, infra.root_path)
    elif sys.argv[1] == "read":
        for event_log_filename in infra.path_event_log.rglob("*ndjson"):
            print(event_log_filename)
            with open(event_log_filename, "rt", encoding="utf-8") as fl:
                for l in fl:
                    event = json.loads(l)
                    print(event)
                    assert verify_event(
                        event["payload"], event["signature"], public_key_hex
                    )
