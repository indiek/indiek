from ik.models import MediaType
from ik.events import create_vertex, create_event, write_event


def run(*, node_content: str, curr_public_key, curr_signing_key, archive_idx):
    # TODO: make this user-controllable when the time comes
    media_type = MediaType.TEXT_PLAIN

    blob_hash = archive_idx.arc.blob_store.create_and_persist_blob(
        node_content, media_type
    )

    body = create_vertex(
        blob_hash=blob_hash,
        data_type=MediaType.TEXT_PLAIN,
        blob_hash_prefix=archive_idx.arc.blob_store.blob_hash_prefix,
    )

    event = create_event(body=body, public_key=curr_public_key, archive=archive_idx)

    write_event(event, curr_signing_key, archive_idx)
