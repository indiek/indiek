from ik.models import MediaType
from ik.events import create_edge, create_event, write_event
from uuid import UUID


def run(
    edge_content, edge_source, edge_target, curr_public_key, curr_signing_key, archive
):
    if edge_source in archive.human_to_machine_id_:
        edge_source = archive.human_to_machine_id_[edge_source]
    if edge_target in archive.human_to_machine_id_:
        edge_target = archive.human_to_machine_id_[edge_target]
    media_type = MediaType.TEXT_PLAIN

    blob_hash = archive.blob_store.create_and_persist_blob(edge_content, media_type)

    body = create_edge(
        source_id=UUID(edge_source),
        target_id=UUID(edge_target),
        blob_hash=blob_hash,
        data_type=MediaType.TEXT_PLAIN,
        blob_hash_prefix=archive.blob_store.blob_hash_prefix,
        archive=archive,
    )

    event = create_event(body=body, public_key=curr_public_key, archive=archive)

    write_event(event, curr_signing_key, archive)
    print(f"ARCHIVE NOW HAS {archive.nevents_} EVENTS")
