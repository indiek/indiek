from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from pprint import pprint
from ik.models import EventModel


def get_nested_value(data: Dict[str, Any], path: str) -> str:
    """
    Helper function to extract a value from a nested dictionary
    using dot notation (e.g., 'header.timestamp').
    """
    keys = path.split(".")
    current = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return "-"  # Fallback if the key doesn't exist

    return str(current)


def print_events_table(
    events: List[Dict[str, Any]], columns_map: Dict[str, str], table_title: str
) -> None:
    """
    Prints a beautiful table to stdout.

    :param events: List of event dictionaries.
    :param columns_map: A dictionary mapping 'Column Display Name' to 'json.path.key'.
    """
    console = Console()

    # Initialize the table with some basic styling
    table = Table(
        show_header=True,
        header_style="bold cyan",
        title=table_title,
        title_style="bold magenta",
    )

    # 1. Add columns dynamically based on the provided map
    for col_name in columns_map.keys():
        # overflow="fold" ensures long hashes don't break the table layout
        table.add_column(col_name, overflow="fold")

    # 2. Extract data and add rows
    for event in events:
        row_data = [get_nested_value(event, path) for path in columns_map.values()]
        table.add_row(*row_data)

    # 3. Render the table to stdout
    console.print(table)


def run(archive):
    # # TODO: use blob_resolver from blob.py
    # for event_dict in archive.event_log:
    #     pprint(event_dict)
    #     event = EventModel(**event_dict)
    #     binary_data = archive.blob_store.load_bin_blob(event.body.blob_hash)
    #     decoded_data = archive.blob_store._bin_encode_decode(
    #         binary_data, event.body.media_type, "decode"
    #     )
    #     print("DECODED DATA", decoded_data)
    #     print("")
    # Define exactly what columns you want to see and where they map to in the JSON
    low_columns = {
        "Timestamp": "header.timestamp",
        "Event Type": "body.event_type",
        "Node ID": "body.node_id",
        "Edge ID": "body.edge_id",
        "Source Node": "body.source_node",
        "Target Node": "body.target_node",
        "Author": "header.author",
    }
    high_columns = {
        "Timestamp": "header.timestamp",
        "Event Type": "body.event_type",
        "Author": "header.author",
    }

    print_events_table(archive.event_log, low_columns, "Events Log")
    print_events_table(archive.meta_event_log, high_columns, "Meta Events Log")


# ==========================================
# Example Usage
# ==========================================
if __name__ == "__main__":
    # Your sample data
    sample_events = [
        {
            "header": {
                "version": "1.0",
                "prev_hash": "cb1c9ca7f07ecfe462a5fdcad043ee14929fe3a6c93b40944aa55e3984ef2003",
                "timestamp": "2026-07-08T03:53:13.571536Z",
                "author": "51e6d165f6f2db95f08fe87b577b4c9fc9d5be9b878f87fdb1d1a1a57d5eefbb",
            },
            "body": {
                "event_type": "create_edge",
                "media_type": "text/plain; charset=utf-8",
                "blob_hash": "sha256:a58a46fce52ef434ba81e2a4fbe75639f76e6a28baab7d29f2c5bd88636b50df",
                "body_type": "edge",
                "edge_id": "019f3fdb-be63-73b0-a010-d992054f89a0",
                "source_node": "019f3bb0-cdc8-71a0-a720-08cda95206a1",
                "target_node": "019f3fd8-5b9d-76f5-a397-fe0907f2db47",
            },
            "signature": "a99fe91e5befbddb9715568ac94ae339dbec6383c0e64d147c8e39e100b68edd854e9765e03ed2db75288e817d42c1d3b3d39a9ea2175199e1baf0c9b0bbef05",
        }
    ]

    # Define exactly what columns you want to see and where they map to in the JSON
    desired_columns = {
        "Timestamp": "header.timestamp",
        "Event Type": "body.event_type",
        "Source Node": "body.source_node",
        "Target Node": "body.target_node",
        "Author Hash": "header.author",
    }

    print_events_table(sample_events, desired_columns)
