from ik.models import Tag, MetaEventType
from ik.events import create_meta_vertex, create_meta_event, write_meta_event


def run(*, tag_name, tag_description, curr_public_key, curr_signing_key, archive_idx):
    # Create a node in the dual network
    body = create_meta_vertex(
        tag=Tag(
            name=tag_name,
            description=tag_description,
            event_type=MetaEventType.CREATE_NODE_TAG,
        )
    )
    event = create_meta_event(
        body=body, public_key=curr_public_key, archive_idx=archive_idx
    )
    write_meta_event(event, curr_signing_key, archive_idx)
