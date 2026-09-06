from uuid import UUID

from indiek.events import create_edge, create_event, write_event
from indiek.models import MediaType


def create_base_edge(
    edge_content,
    edge_source,
    edge_target,
    curr_public_key,
    curr_signing_key,
    archive_idx,
):
    """Create an edge in the base network of the archive

    Args:
        edge_content (_type_): Text data that will become the blob
        edge_source (str): human-friendly or UUID str of the source node
        edge_target (str): human-friendly or UUID str of the target node
        curr_public_key (_type_): _description_
        curr_signing_key (_type_): _description_
        archive_idx (_type_): _description_
    """

    if edge_source in archive_idx.human_to_machine_id_:
        edge_source = archive_idx.human_to_machine_id_[edge_source]
    if edge_target in archive_idx.human_to_machine_id_:
        edge_target = archive_idx.human_to_machine_id_[edge_target]
    media_type = MediaType.TEXT_PLAIN

    blob_hash = archive_idx.arc.blob_store.create_and_persist_blob(
        edge_content, media_type
    )

    body = create_edge(
        source_id=UUID(edge_source),
        target_id=UUID(edge_target),
        blob_hash=blob_hash,
        data_type=MediaType.TEXT_PLAIN,
        blob_hash_prefix=archive_idx.arc.blob_store.blob_hash_prefix,
        archive=archive_idx.arc,
    )

    event = create_event(body=body, public_key=curr_public_key, archive=archive_idx.arc)

    write_event(event, curr_signing_key, arc_idx=archive_idx)
    return str(body.edge_id)


run = create_base_edge  # an alias for the CLI
