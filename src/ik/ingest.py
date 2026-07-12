import logging
from typing import Sequence
from ik.blob import ArchiveIndex
from ik.models import MediaType
from ik.create_node import create_node_from_content
from ik.create_edge import create_base_edge

logger = logging.getLogger(__name__)


def run(
    archive_idx: ArchiveIndex,
    curr_public_key,
    curr_signing_key,
    media_type: MediaType = MediaType.TEXT_PLAIN,
    file_paths: Sequence[str] = (),
    edge_definitions: Sequence[str] = (),
):
    """Ingest data from files.

    Two arguments specify whether nodes and edges will
     be ingested.

    Args:
        archive_idx: ArchiveIndex,
        curr_public_key,
        curr_signing_key,
        media_type: MediaType = MediaType.TEXT_PLAIN,
        file_paths: a list of paths to text files containing node data to ingest
        edge_definitions: a list of str defining the edges to create
    """

    for file_path in file_paths:
        with open(file_path, "rt", encoding="utf-8") as f:
            file_content = f.read()
        create_node_from_content(
            archive_idx, file_content, media_type, curr_public_key, curr_signing_key
        )
        archive_idx = archive_idx.refresh()
        logger.debug("**** INGEST DEBUG")
        logger.debug(f"""
{archive_idx.arc.blob_store.root_path=}
{archive_idx.arc.event_log.root_path=}
{archive_idx.arc.meta_event_log.root_path=}
********
""")
    for edge_def in edge_definitions:
        # TODO: use a more robust CSV parser
        pivot = edge_def.find(",", edge_def.find(",") + 1)
        beginning = edge_def[:pivot]
        source, target = beginning.split(",")
        try:
            content = edge_def[pivot + 1 :]
        except IndexError:
            content = ""

        # TODO: implement tag setting capability
        create_base_edge(
            content,
            source,
            target,
            curr_public_key,
            curr_signing_key,
            archive_idx,
        )
