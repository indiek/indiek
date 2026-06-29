from dotenv import load_dotenv
from signing import get_signing_key, sign_event
import os
from blob import InfraBlobStore
from events import create_node, create_event, write_events

load_dotenv()

# Retrieve the key
my_private_key_hex = os.getenv("GENESIS_AUTHOR_PRIVATE_KEY")
public_key = os.getenv("GENESIS_AUTHOR_PUBLIC_KEY")
signing_key = get_signing_key(my_private_key_hex)

if __name__ == '__main__':

    infra = InfraBlobStore(archive_root = 
    '/Users/adrianradillo/prog/indiek/public_archive/archive/')

    node1_content = "Ohm"
    media_type = "text/plain; charset=utf-8"

    binary_content = infra.bin_encode_decode(
        content=node1_content, 
        content_type=media_type, 
        encode_decode='encode'
        )
    
    # The hash is the ID and determines the storage path
    blob_hash = infra.get_blob_hash(binary_content)

    infra.persist_bin_blob(binary_content, blob_hash)

    json_dict = create_node(
        blob_hash=blob_hash,
        node_type="text/plain; charset=utf-8"
    )
    
    event = create_event(
        payload=json_dict,
        prev_hash=None,
        public_key=public_key
        )
    
    write_events([event], infra.root_path)
