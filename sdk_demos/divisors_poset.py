"""
Division is a preorder on natural integers. For a given highest number, this script
builds the preorder network up to that integer. A directed edge from a to b means that
a divides b.

Edge tags are used to distinguish subtrees by their smallest divisor. So there is one
edge tag per prime number. An edge is tagged with the smallest prime divisor of its
target.
"""

import argparse
from pathlib import Path

from indiek import Archive, Author

MAX = 50


def positive_integer(value: str) -> int:
	"""Parse a positive integer for the upper bound."""
	try:
		number = int(value)
	except ValueError as exc:
		raise argparse.ArgumentTypeError("must be an integer") from exc
	if number < 1:
		raise argparse.ArgumentTypeError("must be at least 1")
	if number > MAX:
		raise argparse.ArgumentError(f"Your integer is too big. Please stay under {MAX}")
	return number


def compute_divisibility_skeleton_edges(n: int) -> list[tuple[int, int]]:
    """
    Computes the edges of the skeleton graph (Hasse diagram/cover graph)
    for the divisibility poset of integers from 1 to N.
    
    An edge (x, y) exists if x divides y and y/x is a prime number.
    """
    if n < 1:
        return []

    # 1. Generate all primes up to N using a simple sieve
    is_prime = [True] * (n + 1)
    primes = []
    for p in range(2, n + 1):
        if is_prime[p]:
            primes.append(p)
            for i in range(p * p, n + 1, p):
                is_prime[i] = False

    # 2. Compute the cover relations (edges)
    edges = []
    for x in range(1, n + 1):
        for p in primes:
            y = x * p
            if y > n:
                break  # Since primes are sorted, any subsequent y will also exceed N
            edges.append((x, y))
            
    return edges, primes

	
def build_divisors_archive(limit: int, folder: Path) -> tuple[int, int]:
	"""Write the divisibility preorder on 1..limit and return node/edge counts."""
	skeleton_edges, primes = compute_divisibility_skeleton_edges(limit)
	archive = Archive.open(folder, author=Author.generate())

	node_ids = {
		number: archive.create_node(str(number), title=str(number))
		for number in range(1, limit + 1)
	}

	prime_tags = {
		prime: archive.create_tag(
			str(prime),
			f"Edge whose target have {prime} as its smallest prime divisor.",
			kind="edge",
		)
		for prime in primes
	}
	edge_count = 0
	for source, target in skeleton_edges:
		edge_id = archive.create_edge(
			node_ids[source], node_ids[target], "divides"
		)
		edge_count += 1
		for prime in primes:
			if (source % prime == 0) and prime != target:
				archive.set_tag(prime_tags[prime], edge_id)
                     
	return len(node_ids), edge_count


if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		description="Create an IndieK archive of the divisibility preorder on 1..N."
	)
	parser.add_argument(
		"integer", type=positive_integer, help="largest integer to include"
	)
	parser.add_argument("folder", type=Path, help="folder for the new IndieK archive")
	args = parser.parse_args()

	archive_folder = args.folder.expanduser()
	if archive_folder.exists():
		if not archive_folder.is_dir():
			parser.error(f"archive path is not a folder: {archive_folder}")
		if any(archive_folder.iterdir()):
			parser.error(f"archive folder is not empty: {archive_folder}")

	nodes, edges = build_divisors_archive(args.integer, archive_folder)
	print(f"Created archive at {archive_folder}: {nodes} nodes, {edges} edges.")
