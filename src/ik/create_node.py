from ik.models import MediaType
from ik.events import create_vertex, create_event, write_event


def run(node_content: str, curr_public_key, curr_signing_key, archive):
    # TODO: make this user-controllable when the time comes
    media_type = MediaType.TEXT_PLAIN

    binary_content: bytes = archive.blob_store.bin_encode_decode(
        content=node_content, content_type=media_type, encode_decode="encode"
    )

    # The hash is the ID and determines the storage path
    blob_hash: str = archive.blob_store.get_blob_hash(binary_content)  # sha256:XXXXX

    archive.blob_store.persist_bin_blob(binary_content, blob_hash)

    body = create_vertex(
        blob_hash=blob_hash,
        data_type=MediaType.TEXT_PLAIN,
        blob_hash_prefix=archive.blob_store.blob_hash_prefix,
    )

    event = create_event(body=body, public_key=curr_public_key, archive=archive)

    write_event(event, curr_signing_key, archive)
    print(f"ARCHIVE NOW HAS {archive.nevents_} EVENTS")
