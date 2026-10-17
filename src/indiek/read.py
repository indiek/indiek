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

from typing import Any, Callable, Dict, Iterable
from uuid import UUID

from rich.console import Console
from rich.table import Table

from indiek import Archive


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
    events: Iterable[Dict[str, Any]],
    columns_map: Dict[str, str],
    table_title: str,
    alias_of: Callable[[UUID], str],
) -> None:
    """
    Prints a table to stdout.

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
    table.add_column("Human-Friendly ID", overflow="fold")

    # 2. Extract data and add rows
    for event in events:
        row_data = [get_nested_value(event, path) for path in columns_map.values()]
        if "node_id" in event["body"].keys():
            row_data.append(alias_of(UUID(event["body"]["node_id"])))
        elif "edge_id" in event["body"].keys():
            row_data.append(alias_of(UUID(event["body"]["edge_id"])))
        table.add_row(*row_data)

    # 3. Render the table to stdout
    console.print(table)


def run(ik: Archive, mini: bool) -> None:
    low_columns = {
        "Timestamp": "header.timestamp",
        "Event Type": "body.event_type",
        "Author": "header.author",
    }
    high_columns = {
        "Timestamp": "header.timestamp",
        "Event Type": "body.event_type",
        "Author": "header.author",
        "Tag Name": "body.name",
    }
    if not mini:
        low_columns.update(
            {
                "Node ID": "body.node_id",
                "Edge ID": "body.edge_id",
                "Source Node": "body.source_node",
                "Target Node": "body.target_node",
                "Resource Type": "body.resource_type",
                "Title": "body.title",
            }
        )
        high_columns.update(
            {
                "Meta Node ID": "body.node_id",
                "Meta Edge ID": "body.edge_id",
                "Tag Description": "body.description",
                "Meta Source Node": "body.source_node",
                "Meta Target Node": "body.target_node",
                "Underlying ID": "body.underlying_id",
            }
        )

    print_events_table(ik.events("base"), low_columns, "Events Log", ik.index.alias_of)
    print_events_table(
        ik.events("meta"), high_columns, "Meta Events Log", ik.index.alias_of
    )
