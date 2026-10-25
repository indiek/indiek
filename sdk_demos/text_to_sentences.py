"""
TODO: This example needs some thinking/tinkering/reworking. Mostly UI-design work though...
Turn input text into a network of connected words.

Each distinct word becomes one node. A directed edge connects each pair of
consecutive words in a sentence. Node tags identify each word's 1-indexed
position in a sentence, and edge tags identify the sentence number.
"""

import argparse
import re
from pathlib import Path

from indiek import Archive, Author

DELIMITERS = ".!?"
WORD_DELIMITERS = " ;,"


def split_on_delimiters(text: str, delimiters: str) -> list[str]:
    """Split on any configured delimiter, trimming and dropping empty parts."""
    pattern = f"[{re.escape(delimiters)}]+"
    return [part.strip() for part in re.split(pattern, text) if part.strip()]


def create_network(sentence_list: list[str], archive: Archive) -> tuple[int, int]:
    """Write word nodes, positional node tags, sentence edges, and edge tags."""
    word_to_node_id: dict[str, object] = {}
    position_to_tag: dict[int, object] = {}
    edge_count = 0

    for sentence_number, sentence in enumerate(sentence_list, start=1):
        words = split_on_delimiters(sentence, WORD_DELIMITERS)
        if not words:
            continue

        sentence_tag = archive.create_tag(
            f"S{sentence_number}",
            f"Sentence number {sentence_number}",
            kind="edge",
        )
        sentence_nodes = []

        for word_position, word in enumerate(words, start=1):
            if word not in word_to_node_id:
                word_to_node_id[word] = archive.create_node(word, title=word)
            node_id = word_to_node_id[word]
            sentence_nodes.append(node_id)

            if word_position not in position_to_tag:
                position_to_tag[word_position] = archive.create_tag(
                    f"w{word_position}",
                    f"Position {word_position} in sentence.",
                    kind="node",
                )
            archive.set_tag(position_to_tag[word_position], node_id)

        for source, target in zip(sentence_nodes, sentence_nodes[1:]):
            edge_id = archive.create_edge(source, target, "next")
            archive.set_tag(sentence_tag, edge_id)
            edge_count += 1

    return len(word_to_node_id), edge_count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create an IndieK word network from text."
    )
    parser.add_argument("text", help="text to split into sentences and words")
    parser.add_argument("folder", type=Path, help="folder for the new IndieK archive")
    args = parser.parse_args()

    archive_folder = args.folder.expanduser()
    if archive_folder.exists():
        if not archive_folder.is_dir():
            parser.error(f"archive path is not a folder: {archive_folder}")
        if any(archive_folder.iterdir()):
            parser.error(f"archive folder is not empty: {archive_folder}")

    sentences = split_on_delimiters(args.text, DELIMITERS)
    archive = Archive.open(archive_folder, author=Author.generate())
    nodes, edges = create_network(sentences, archive)
    print(f"Created archive at {archive_folder}: {nodes} nodes, {edges} edges.")