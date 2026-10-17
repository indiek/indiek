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

---

Export the base network as GraphML."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any
from uuid import UUID
from xml.dom import minidom

from indiek.core.index import ArchiveIndex
from indiek.core.models import MediaType


def build_graphml_tree(
    events: Iterable[dict[str, Any]], blob_resolver: Callable[[str], str]
) -> ET.ElementTree:
    """Build a directed GraphML tree from base-network event dicts.

    Only ``create_node`` / ``create_edge`` events become elements;
    ``blob_resolver`` maps a ``text/plain`` blob hash to its label text.
    """
    # TODO(CLIPYPI:EXPORT-SUPERSEDES): project supersedes, drop dangling edges
    root = ET.Element(
        "graphml",
        attrib={
            "xmlns": "http://graphml.graphdrawing.org/xmlns",
            "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "xsi:schemaLocation": "http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd",
        },
    )
    keys = [
        ("node_author", "node", "author", "string"),
        ("node_timestamp", "node", "timestamp", "string"),
        ("node_hash", "node", "blob_hash", "string"),
        ("node_label", "node", "label", "string"),
        ("edge_author", "edge", "author", "string"),
        ("edge_timestamp", "edge", "timestamp", "string"),
        ("edge_hash", "edge", "blob_hash", "string"),
        ("edge_label", "edge", "label", "string"),
    ]
    for k_id, k_for, k_name, k_type in keys:
        ET.SubElement(
            root,
            "key",
            id=k_id,
            **{"for": k_for, "attr.name": k_name, "attr.type": k_type},
        )
    graph = ET.SubElement(
        root, "graph", id="ik_knowledge_graph", edgedefault="directed"
    )

    for event in events:
        header = event.get("header", {})
        body = event.get("body", {})
        event_type = body.get("event_type")
        author = header.get("author", "")
        timestamp = header.get("timestamp", "")
        blob_hash = body.get("blob_hash", "")
        label_text = ""
        if blob_hash and body.get("media_type", "") == MediaType.TEXT_PLAIN.value:
            label_text = blob_resolver(blob_hash)

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


def export_graphml(
    index: ArchiveIndex,
    output_path: str | Path,
    tags: Sequence[str | UUID] = (),
) -> Path:
    """Write the base network to ``output_path`` (overwritten) as pretty GraphML.

    With ``tags``, keep only items carrying at least one of them (OR); nodes
    and edges are filtered independently.
    """
    wanted = {index.resolve(tag) for tag in tags}

    def has_wanted_tag(event: dict[str, Any]) -> bool:
        body = event["body"]
        item_id = UUID(body["node_id"] if "node_id" in body else body["edge_id"])
        return bool(index.items[item_id].tags & wanted)

    events: Iterable[dict[str, Any]] = index.store.base_log
    if wanted:
        events = filter(has_wanted_tag, events)
    tree = build_graphml_tree(events, index.store.blobs.get_text)
    raw_xml = ET.tostring(tree.getroot(), encoding="utf-8")
    pretty_xml = minidom.parseString(raw_xml).toprettyxml(indent="  ")
    path = Path(output_path)
    path.write_text(pretty_xml, encoding="utf-8")
    return path
