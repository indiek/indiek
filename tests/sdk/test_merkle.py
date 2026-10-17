"""``blob_root``: the Merkle root sealed over the blob store (CLIPYPI:SEAL-LOG).

Owner decision D9: leaves hash the raw 32-byte digest, so ``blob_root`` is
the RFC 6962 Merkle Tree Hash over the sorted blob digests.  The reference
below is RFC 6962 section 2.1 verbatim (split at the largest power of two),
independent of the SDK's level-by-level implementation.
"""

from __future__ import annotations

import hashlib
import json
import random
from importlib.resources import files

import pytest

from indiek import IntegrityError
from indiek.core.merkle import blob_root


def _rfc6962(leaves: list[bytes]) -> bytes:
    """RFC 6962 MTH(D[n]) over already-encoded leaf data."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    left, right = _rfc6962(leaves[:k]), _rfc6962(leaves[k:])
    return hashlib.sha256(b"\x01" + left + right).digest()


def _digests(n: int, seed: int = 0) -> list[str]:
    rng = random.Random(seed)
    return [hashlib.sha256(rng.randbytes(8)).hexdigest() for _ in range(n)]


def _expected(digests: list[str]) -> str:
    raw = [bytes.fromhex(d) for d in sorted(digests)]
    return "sha256:" + _rfc6962(raw).hex()


def test_empty_store_is_the_hash_of_nothing() -> None:
    assert blob_root([]) == "sha256:" + hashlib.sha256(b"").hexdigest()


def test_single_blob_is_its_leaf_hash() -> None:
    (digest,) = _digests(1)
    leaf = hashlib.sha256(b"\x00" + bytes.fromhex(digest)).hexdigest()
    assert blob_root([digest]) == f"sha256:{leaf}"


@pytest.mark.parametrize("n", range(2, 18))
def test_matches_rfc6962_for_every_tree_shape(n: int) -> None:
    digests = _digests(n, seed=n)
    assert blob_root(digests) == _expected(digests)


def test_input_order_does_not_matter_and_prefixes_are_accepted() -> None:
    digests = _digests(5)
    shuffled = list(reversed(digests))
    prefixed = [f"sha256:{d}" for d in digests]
    assert blob_root(shuffled) == blob_root(digests) == blob_root(prefixed)


def test_any_added_or_missing_blob_changes_the_root() -> None:
    digests = _digests(4)
    root = blob_root(digests)
    assert blob_root(digests[:-1]) != root
    assert blob_root([*digests, *_digests(1, seed=99)]) != root


def test_leaves_and_inner_nodes_are_domain_separated() -> None:
    """Two leaves cannot pass for one leaf holding their concatenated parent."""
    a, b = _digests(2)
    leaf = lambda d: hashlib.sha256(b"\x00" + bytes.fromhex(d)).digest()  # noqa: E731
    fake = hashlib.sha256(leaf(a) + leaf(b)).hexdigest()  # parent without 0x01
    assert blob_root([a, b]) != f"sha256:{fake}"


@pytest.mark.parametrize(
    "name", ["not-hex", "ab" * 31, "AB" * 32, ".DS_Store", "md5:" + "ab" * 16]
)
def test_invalid_blob_names_are_integrity_errors(name: str) -> None:
    with pytest.raises(IntegrityError, match="Invalid blob name"):
        blob_root([*_digests(2), name])


def test_shipped_merkle_vectors_are_reproduced() -> None:
    raw = files("indiek").joinpath("spec", "test_vectors.json").read_text("utf-8")
    vectors = json.loads(raw)["merkle_vectors"]
    assert [len(v["leaves"]) for v in vectors] == [0, 1, 2, 3, 5]
    for vector in vectors:
        assert blob_root(vector["leaves"]) == vector["root"]
        assert _expected(vector["leaves"]) == vector["root"]
