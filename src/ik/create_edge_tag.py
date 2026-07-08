from ik.models import Tag
from ik.events import create_meta_vertex, create_meta_event, write_meta_event


def run(*, tag_name, tag_description, curr_public_key, curr_signing_key, archive):
    # Create a node in the dual network
    body = create_meta_vertex(tag=Tag(name=tag_name, description=tag_description))
    event = create_meta_event(body=body, public_key=curr_public_key, archive=archive)
    write_meta_event(event, curr_signing_key, archive)

    print(f"ARCHIVE NOW HAS {archive.n_meta_events_} META EVENTS")
