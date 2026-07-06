"""Code to generate and I/O blobs"""

from typing import Any, Tuple
import os
import json
from pathlib import Path
import hashlib
from ik.signing import verify_signature, get_canonical_hash
from ik.models import MediaType


class IntegrityError(Exception):
    """The archive is corrupted"""

    pass


class FileExistsException(Exception):
    """File Exists"""

    pass


class InfraIO:
    def __init__(self, archive_root):
        self.root_path = Path(archive_root)


class InfraEventLog(InfraIO):
    # TODO: Render iterable - for event in InfraEventLog
    def __init__(self, archive_root):
        super().__init__(archive_root)
        self.path_event_log = self.root_path.joinpath("events")

    def __iter__(self):
        for event_log_filename in self.path_event_log.rglob("*ndjson"):
            with open(event_log_filename, "rt", encoding="utf-8") as f:
                for event_line in f:
                    yield json.loads(event_line)


class InfraBlobStore(InfraIO):
    def __init__(self, archive_root):
        super().__init__(archive_root)
        self.blob_hash_prefix = "sha256:"
        self.blobs_path = os.path.join(self.root_path, "blobs", "sha256")

    def create_and_persist_blob(self, content, media_type):
        binary_content: bytes = self._bin_encode_decode(
            content=content, content_type=media_type, encode_decode="encode"
        )

        # The hash is the ID and determines the storage path
        blob_hash: str = self._get_blob_hash(binary_content)  # sha256:XXXXX

        self._persist_bin_blob(binary_content, blob_hash)
        return blob_hash

    def _get_blob_hash(self, bin_blob):
        return hashlib.sha256(bin_blob).hexdigest()

    def _bin_encode_decode(self, content: Any, content_type: str, encode_decode: str):
        if content_type == MediaType.TEXT_PLAIN and encode_decode == "encode":
            return content.encode(encoding="utf-8")
        if content_type == MediaType.TEXT_PLAIN and encode_decode == "decode":
            return str(content, encoding="utf-8")

    def _persist_bin_blob(self, bin_content, sha256_hex):
        """
        Persists binary data using a sharded content-addressable path.
        Example: blobs/a1/b2/a1b2c3d4...
        """
        # Create directory structure using first 4 chars of hash (sharding)
        prefix1 = sha256_hex[:2]
        prefix2 = sha256_hex[2:4]

        dir_path = os.path.join(self.blobs_path, prefix1, prefix2)
        os.makedirs(dir_path, exist_ok=True)

        # Write the file named by its hash
        file_path = os.path.join(dir_path, sha256_hex)

        # Only write if file doesn't exist (Content-addressing is immutable)
        if not os.path.exists(file_path):
            with open(file_path, "wb") as f:
                f.write(bin_content)
            print(f"BLOB FILE WRITTEN TO {file_path}")
        else:
            # TODO: handle the warning below better
            print("***WARNING*** FILE EXISTS; NOTHING ADDITIONAL WRITTEN IN blobs/")

    def load_bin_blob(self, blob_hash_from_json: str) -> bytes:
        skip = len(self.blob_hash_prefix)
        sha256_hex = blob_hash_from_json[skip:]
        prefix1 = sha256_hex[:2]
        prefix2 = sha256_hex[2:4]
        dir_path = os.path.join(self.blobs_path, prefix1, prefix2)
        file_path = os.path.join(dir_path, sha256_hex)
        with open(file_path, "rb") as f:
            return f.read()


class Archive:
    def __init__(
        self,
        event_log: InfraEventLog,
        blob_store: InfraBlobStore,
        check_integrity: bool = True,
    ):
        self.event_log = event_log
        self.blob_store = blob_store
        self.last_event_hash_: str | None = None
        self.nevents_ = None
        if check_integrity:
            self.last_event_hash_, self.nevents_ = self.check_archive_integrity()

    def check_archive_integrity(self) -> Tuple[str, int]:
        # TODO: currently doesn't check public keys against MANIFEST
        real_prev_hash = None  # for scenario where event log is empty
        ecount = 0
        for ecount, event in enumerate(self.event_log):
            # 1. check that the stored previous hash matches the real previous hash
            if ecount:  # nothing to check for genesis event
                stored_prev_hash = event["header"]["prev_hash"]
                if real_prev_hash != stored_prev_hash:
                    raise IntegrityError("Chain broken!")

            # 2. Check Signature
            public_key_hex = event["header"]["author"]
            if not verify_signature(event["body"], event["signature"], public_key_hex):
                raise IntegrityError("Data tampered or bad author!")

            # 3. Check Blobs (if applicable)
            if "blob_hash" in event["body"]:
                if not self.verify_blob_on_disk(event["body"]["blob_hash"]):
                    raise IntegrityError("File corrupted or missing!")

            # prepare for next iteration
            real_prev_hash = get_canonical_hash(event).hex()

        print("ARCHIVE INTEGRITY VERIFIED")
        return real_prev_hash, ecount + int(real_prev_hash is not None)

    def verify_blob_on_disk(self, blob_hash):
        binary_data = self.blob_store.load_bin_blob(blob_hash)
        real_hash = self.blob_store._get_blob_hash(binary_data)
        given = blob_hash[len(self.blob_store.blob_hash_prefix) :]
        return given == real_hash
