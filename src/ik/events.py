import os
from uuid import UUID
from ik.signing import sign_event, get_canonical_hash
from ik.blob import Archive
from ik.models import EventModel, Node, EventBody, EventHeader, Edge, EventType


def create_event(body: EventBody, public_key: str, archive: Archive) -> EventModel:

    prev_hash = archive.last_event_hash_ if archive.nevents_ else None

    return EventModel(  # signatre None at creation
        header=EventHeader(  # timestamp default factory
            version="1.0", prev_hash=prev_hash, author=public_key
        ),
        body=body,
    )


def create_vertex(blob_hash, data_type, blob_hash_prefix) -> Node:
    return Node(  # node_id default factory
        event_type=EventType.CREATE_NODE,
        media_type=data_type,
        blob_hash=blob_hash_prefix + blob_hash,
    )


def create_edge(
    source_id: UUID,
    target_id: UUID,
    blob_hash,
    data_type,
    blob_hash_prefix,
    archive: Archive,
) -> Edge:
    # verify that source and target exist
    source_present, target_present = False, False
    for event in archive.event_log:
        try:
            eid = UUID(event["body"]["node_id"])
            if eid == source_id:
                source_present = True
            if eid == target_id:
                target_present = True
        except KeyError:  # the event is not about a node
            continue
    if not source_present:
        raise ValueError(f"SOURCE NODE {source_id} NOT FOUND IN ARCHIVE")
    if not target_present:
        raise ValueError(f"TARGET NODE {target_id} NOT FOUND IN ARCHIVE")
    return Edge(
        event_type=EventType.CREATE_EDGE,
        media_type=data_type,
        blob_hash=blob_hash_prefix + blob_hash,
        source_node=source_id,
        target_node=target_id,
    )


def sign_unsigned_event(event, signing_key):
    event.signature = sign_event(event.body, signing_key)


def write_event(event: EventModel, signing_key, arc: Archive):

    sign_unsigned_event(event, signing_key)
    event_hash = get_canonical_hash(event)

    # Extract date from event header
    ts = event.header.timestamp

    # Create path: /archive/events/YYYY/MM/DD/
    dir_path = os.path.join(arc.event_log.path_event_log, ts.strftime("%Y/%m/%d"))
    os.makedirs(dir_path, exist_ok=True)

    # Append to the daily log
    file_path = os.path.join(dir_path, "events.ndjson")
    event_json_str = event.model_dump_json()
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(event_json_str + "\n")
    print(f"EVENT {event_json_str} WRITTEN TO {file_path}")
    arc.last_event_hash_ = event_hash
    arc.nevents_ += 1
