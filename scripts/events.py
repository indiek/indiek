"""
from pydantic import ValidationError

valid_payload = {
    "header": {
        "prev_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", # 64 chars
        "author": "9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c"    # 64 chars
    },
    "body": {
        "media_type": "video/mp4",
        "blob_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"   # Raw hex
    }
}

try:
    event = EventModel(**valid_payload)
    print("Successfully prepended prefix:")
    print(event.body.blob_hash) # Output: sha256:e3b0c442...
except ValidationError as e:
    print(e)

"""

import os
from datetime import datetime
from signing import sign_event, get_canonical_hash
from blob import Archive
from models import EventModel, EventBody, EventHeader


def create_event(payload: EventBody, public_key: str, archive: Archive) -> EventModel:

    prev_hash = archive.last_event_hash_ if archive.nevents_ else None

    return EventModel(
        header=EventHeader(  # timestamp default factory
            version="1.0", prev_hash=prev_hash, author=public_key
        ),
        body=payload,
    )


def create_node(blob_hash, data_type, blob_hash_prefix) -> EventBody:
    return EventBody(  # node_id default factory
        event_type="create_node",
        media_type=data_type,
        blob_hash=blob_hash_prefix + blob_hash,
    )


def sign_unsigned_event(event, signing_key):
    event.signature = sign_event(event.body, signing_key)


def write_event(event: EventModel, signing_key, arc: Archive):

    sign_unsigned_event(event, signing_key)
    event_hash = get_canonical_hash(event)

    # Extract date from event header
    ts_str = event.header.timestamp.replace("Z", "+00:00")
    ts = datetime.fromisoformat(ts_str)

    # Create path: /archive/events/YYYY/MM/DD/
    dir_path = os.path.join(arc.event_log.path_event_log, ts.strftime("%Y/%m/%d"))
    os.makedirs(dir_path, exist_ok=True)

    # Append to the daily log
    file_path = os.path.join(dir_path, "events.ndjson")
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(event.model_dump_json() + "\n")
    arc.last_event_hash_ = event_hash
