from pprint import pprint
from ik.models import EventModel, MediaType


def run(archive):
    # TODO: use blob_resolver from blob.py
    for event_dict in archive.event_log:
        pprint(event_dict)
        event = EventModel(**event_dict)
        binary_data = archive.blob_store.load_bin_blob(event.body.blob_hash)
        decoded_data = archive.blob_store._bin_encode_decode(
            binary_data, event.body.media_type, "decode"
        )
        print("DECODED DATA", decoded_data)
        print("")
