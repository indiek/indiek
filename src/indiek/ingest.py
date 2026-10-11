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
from pathlib import Path
from typing import Sequence

from indiek.blob import ArchiveIndex
from indiek.create_edge import create_base_edge
from indiek.create_node import create_node_from_content, extract_content_and_mime

logger = logging.getLogger(__name__)


def run(
    *,
    archive_idx: ArchiveIndex,
    curr_public_key,
    curr_signing_key,
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
        file_content, media_type = extract_content_and_mime(file_path)
        title = Path(file_path).stem
        create_node_from_content(
            archive_idx,
            file_content,
            media_type,
            curr_public_key,
            curr_signing_key,
            title,
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
        archive_idx = archive_idx.refresh()
