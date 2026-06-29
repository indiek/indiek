"""Code to generate and I/O blobs"""
from types import Any
import os
from pathlib import Path
import hashlib

class InfraBlobStore:
    def __init__(self, archive_root):
        self.root_path = Path(archive_root)

    # def read(self, object_path):
    #     with open(object_path, mode='r') as f:
    #         return f.read()
        
    def get_blob_hash(self, bin_blob):
        return hashlib.sha256(bin_blob).hexdigest()

    def bin_encode_decode(self, content: Any, content_type: str, encode_decode: str):
        if content_type == "text/plain; charset=utf-8" and encode_decode == 'encode':
            return content.encode(encoding='utf-8')

    def persist_bin_blob(self, bin_content, sha256_hex):
        """
        Persists binary data using a sharded content-addressable path.
        Example: blobs/a1/b2/a1b2c3d4...
        """
        # Create directory structure using first 4 chars of hash (sharding)
        prefix1 = sha256_hex[:2]
        prefix2 = sha256_hex[2:4]
        
        dir_path = os.path.join(self.root_path, "blobs", prefix1, prefix2)
        os.makedirs(dir_path, exist_ok=True)
        
        # Write the file named by its hash
        file_path = os.path.join(dir_path, sha256_hex)
        
        # Only write if file doesn't exist (Content-addressing is immutable)
        if not os.path.exists(file_path):
            with open(file_path, "wb") as f:
                f.write(bin_content)

    # def load_bin_blob(self, bin_hash):
    #     return self.read(self.hash_path_conversion(bin_hash, direction="hash_to_path"))