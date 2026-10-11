"""Copyright 2026 Adrian Ernesto Radillo

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import logging
from uuid import UUID

from indiek.blob import Archive, ArchiveIndex
from indiek.events import (
    create_meta_edge,
    create_meta_event,
    create_representation,
    write_meta_event,
)
from indiek.models import MetaEventType

logger = logging.getLogger(__name__)


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
    if queried_uuid not in archive_idx.id_info_:
        raise ValueError("UUID is not part of any network (neither base nor meta)")
    item_info = archive_idx.id_info_[queried_uuid]
    if item_info["is_meta"]:
        raise ValueError("UUID should not be an item from the meta network")
    if item_info["is_edge"]:
        node_or_edge_repr = MetaEventType.CREATE_EDGE_REPRESENTATION
    else:
        node_or_edge_repr = MetaEventType.CREATE_NODE_REPRESENTATION
    # create representation of the target if it doesn't exist yet
    created_representation = False
    if queried_uuid not in archive_idx.underlying_id_to_repr_id_:
        logger.debug("...Creating non-existent representation first")
        created_representation = True
        edge_target: UUID = create_representation(
            underlying_uuid_str=underlying_target,
            correct_event=node_or_edge_repr,
            public_key=curr_public_key,
            archive_index=archive_idx,
            signing_key=curr_signing_key,
        )
        logger.debug("...Refreshing archive and index")
        refreshed_archive = Archive(
            event_log=archive_idx.arc.event_log,
            meta_event_log=archive_idx.arc.meta_event_log,
            blob_store=archive_idx.arc.blob_store,
        )
        archive_idx = ArchiveIndex(refreshed_archive)
    else:
        edge_target: UUID = archive_idx.underlying_id_to_repr_id_[queried_uuid]
    logger.debug("...Now creating the meta edge")
    try:
        body = create_meta_edge(
            source_id=meta_source_uuid,
            target_id=edge_target,
            archive_idx=archive_idx,
        )
    except ValueError:
        # Intended: a representation written above is kept even though no tag
        # is set, so the user is told it remains in the meta log.
        if created_representation:
            logger.warning(
                "set_tag rejected: representation %s of %s was created but no "
                "tag was set; the representation remains in the meta log "
                "(intended, harmless).",
                edge_target,
                queried_uuid,
            )
        raise

    event = create_meta_event(
        body=body, public_key=curr_public_key, archive_idx=archive_idx
    )

    write_meta_event(event, curr_signing_key, archive_idx)
