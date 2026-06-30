import time
import json
import os
from datetime import datetime
import uuid
from typing import Dict
from signing import sign_event


def create_event(payload, prev_hash, public_key, first_event: bool = False):
    if first_event:
        assert prev_hash is None, "first event cannot have a predecessor"
    else:
        assert (
            prev_hash is not None
        ), "only the first event is allowed to have no predecessor"
    event = {
        "header": {
            "version": "1.0",
            "prev_hash": prev_hash,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "author": public_key,
        },
        "payload": payload,
    }
    return event


def create_node(blob_hash, data_type, blob_hash_prefix) -> Dict:
    return {
        "event_type": "create_node",
        "node_id": str(uuid.uuid7()),
        "media_type": data_type,
        "blob_hash": blob_hash_prefix + blob_hash,
    }


def sign_unsigned_events(events, signing_key):
    for event in events:
        event["signature"] = sign_event(event["payload"], signing_key)


def write_events(list_of_events, signing_key, base_path):

    sign_unsigned_events(list_of_events, signing_key)
    for event in list_of_events:
        # Extract date from event header
        ts_str = event["header"]["timestamp"].replace("Z", "+00:00")
        ts = datetime.fromisoformat(ts_str)

        # Create path: /archive/events/YYYY/MM/DD/
        dir_path = os.path.join(base_path, "events", ts.strftime("%Y/%m/%d"))
        os.makedirs(dir_path, exist_ok=True)

        # Append to the daily log
        file_path = os.path.join(dir_path, "events.ndjson")
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
