from ik.blob import ArchiveIndex
from ik.models import MediaType
from ik.create_node import create_node_from_content


def run(
    file_paths,
    archive_idx: ArchiveIndex,
    curr_public_key,
    curr_signing_key,
    media_type: MediaType = MediaType.TEXT_PLAIN,
):
    """Ingest a collection of text files as nodes."""
    for file_path in file_paths:
        with open(file_path, "rt", encoding="utf-8") as f:
            file_content = f.read()
        create_node_from_content(
            archive_idx, file_content, media_type, curr_public_key, curr_signing_key
        )
        archive_idx = archive_idx.refresh()
