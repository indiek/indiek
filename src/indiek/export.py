import xml.etree.ElementTree as ET
from typing import Callable, Iterable, Sequence
from uuid import UUID
from xml.dom import minidom

from indiek.blob import ArchiveIndex
from indiek.models import MediaType


def build_graphml_tree(events: Iterable, blob_resolver: Callable) -> ET.ElementTree:
    """
    Parses a sequence of ik events and builds a GraphML XML tree.

    Args:
        events: An iterable of parsed event dictionaries (from events.ndjson).
        blob_resolver:

    Returns:
        An xml.etree.ElementTree object representing the graph.
    """
    # 1. Initialize root and namespaces
    # GraphML requires specific namespaces to be valid for standard visualizers
    root = ET.Element(
        "graphml",
        attrib={
            "xmlns": "http://graphml.graphdrawing.org/xmlns",
            "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "xsi:schemaLocation": "http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd",
        },
    )

    # 2. Define Data Keys (The Schema of the GraphML)
    keys = [
        # Node attributes
        ("node_author", "node", "author", "string"),
        ("node_timestamp", "node", "timestamp", "string"),
        ("node_hash", "node", "blob_hash", "string"),
        ("node_label", "node", "label", "string"),  # For the resolved text content
        # Edge attributes
        ("edge_author", "edge", "author", "string"),
        ("edge_timestamp", "edge", "timestamp", "string"),
        ("edge_hash", "edge", "blob_hash", "string"),
        ("edge_label", "edge", "label", "string"),  # For the resolved text content
    ]

    for k_id, k_for, k_name, k_type in keys:
        ET.SubElement(
            root,
            "key",
            id=k_id,
            **{"for": k_for, "attr.name": k_name, "attr.type": k_type},
        )

    # 3. Initialize the Directed Graph
    graph = ET.SubElement(
        root, "graph", id="ik_knowledge_graph", edgedefault="directed"
    )

    # 4. Process Events Append-Only Log
    for event in events:
        header = event.get("header", {})
        body = event.get("body", {})
        event_type = body.get("event_type")

        # Extract metadata common to all events
        author = header.get("author", "")
        timestamp = header.get("timestamp", "")
        blob_hash = body.get("blob_hash", "")
        media_type = body.get("media_type", "")

        # Resolve text content if a resolver is provided
        label_text = ""

        if blob_hash and media_type == MediaType.TEXT_PLAIN.value:
            label_text = blob_resolver(blob_hash, media_type)

        if event_type == "create_node":
            node_id = body.get("node_id")
            if not node_id:
                continue

            node = ET.SubElement(graph, "node", id=node_id)
            ET.SubElement(node, "data", key="node_author").text = author
            ET.SubElement(node, "data", key="node_timestamp").text = timestamp
            ET.SubElement(node, "data", key="node_hash").text = blob_hash
            if label_text:
                ET.SubElement(node, "data", key="node_label").text = label_text

        elif event_type == "create_edge":
            edge_id = body.get("edge_id")
            source = body.get("source_node")
            target = body.get("target_node")

            if not all([edge_id, source, target]):
                continue

            edge = ET.SubElement(
                graph, "edge", id=edge_id, source=source, target=target
            )
            ET.SubElement(edge, "data", key="edge_author").text = author
            ET.SubElement(edge, "data", key="edge_timestamp").text = timestamp
            ET.SubElement(edge, "data", key="edge_hash").text = blob_hash
            if label_text:
                ET.SubElement(edge, "data", key="edge_label").text = label_text

    return ET.ElementTree(root)


def run(archive_idx: ArchiveIndex, output_path: str, tags: Sequence[str]):
    """
    Builds the GraphML and writes it to disk with pretty-printing.
    """
    tags_uuid = set()
    for human_tag in tags:
        try:
            as_uuid = UUID(human_tag)
        except ValueError:
            as_uuid = UUID(archive_idx.human_to_machine_id_[human_tag])
        tags_uuid.update({as_uuid})

    def tag_filter(event_dict):
        try:
            item_id = UUID(event_dict["body"]["node_id"])
        except KeyError:
            item_id = UUID(event_dict["body"]["edge_id"])
        tags_from_info = archive_idx.id_info_[item_id]["tags"]
        return bool(tags_from_info.intersection(tags_uuid))

    if tags_uuid:
        filtered_event_log = filter(tag_filter, archive_idx.arc.event_log)
    else:
        filtered_event_log = archive_idx.arc.event_log
    tree = build_graphml_tree(
        filtered_event_log, archive_idx.arc.blob_store.blob_resolver
    )
    # TODO: implement sticky nodes to dangling edges
    root = tree.getroot()

    # Generate raw string
    raw_xml = ET.tostring(root, encoding="utf-8")

    # Pretty print using minidom for human readability
    parsed_xml = minidom.parseString(raw_xml)
    pretty_xml = parsed_xml.toprettyxml(indent="  ")

    # Write to file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(pretty_xml)
