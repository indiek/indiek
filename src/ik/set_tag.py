from uuid import UUID
from ik.events import (
    create_meta_edge,
    create_meta_event,
    write_meta_event,
    create_representation,
)
from ik.models import MetaEventType
from ik.blob import ArchiveIndex, Archive


def run(
    *,
    edge_source: str,
    underlying_target: str,
    curr_public_key,
    curr_signing_key,
    archive_idx: ArchiveIndex,
):

    if edge_source in archive_idx.human_to_machine_id_:
        edge_source = archive_idx.human_to_machine_id_[edge_source]
    meta_source_uuid = UUID(edge_source)

    # check that the source indeed is a tag in the meta network
    archive_idx.assert_node_is_tag(meta_source_uuid)

    # check that the author using the tag is the author of the tag
    archive_idx.confirm_tag_authorship(curr_public_key, meta_source_uuid)

    if underlying_target in archive_idx.human_to_machine_id_:
        underlying_target = archive_idx.human_to_machine_id_[underlying_target]
    # now the underlying target is a str corresponding to a proper UUID
    queried_uuid = UUID(underlying_target)
    # confirm the underlying target is an existing ID from the base network
    assert (
        queried_uuid in archive_idx.id_info_.keys()
    ), "UUID is not part of any network (neither base nor meta)"
    item_info = archive_idx.id_info_[queried_uuid]
    assert not item_info["is_meta"], "UUID should not be an item from the meta network"
    if item_info["is_edge"]:
        node_or_edge_repr = MetaEventType.CREATE_EDGE_REPRESENTATION
    else:
        node_or_edge_repr = MetaEventType.CREATE_NODE_REPRESENTATION
    # create representation of the target if it doesn't exist yet
    if queried_uuid not in archive_idx.underlying_id_to_repr_id_:
        print("...Creating non-existent representation first")
        edge_target: UUID = create_representation(
            underlying_uuid_str=underlying_target,
            correct_event=node_or_edge_repr,
            public_key=curr_public_key,
            archive_index=archive_idx,
            signing_key=curr_signing_key,
        )
        print("...Refreshing archive and index")
        refreshed_archive = Archive(
            event_log=archive_idx.arc.event_log,
            meta_event_log=archive_idx.arc.meta_event_log,
            blob_store=archive_idx.arc.blob_store,
        )
        archive_idx = ArchiveIndex(refreshed_archive)
    else:
        edge_target: UUID = archive_idx.underlying_id_to_repr_id_[queried_uuid]
    print("...Now creating the meta edge")
    body = create_meta_edge(
        source_id=meta_source_uuid,
        target_id=edge_target,
        archive_idx=archive_idx,
    )

    event = create_meta_event(
        body=body, public_key=curr_public_key, archive_idx=archive_idx
    )

    write_meta_event(event, curr_signing_key, archive_idx)
