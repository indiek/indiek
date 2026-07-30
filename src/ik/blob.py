"""Code to generate and I/O blobs"""

from typing import Any, Tuple
import logging
import os
import json
from uuid import UUID
from pathlib import Path
import hashlib
from ik.signing import verify_signature, get_canonical_hash
from ik.models import MediaType, EventType, MetaEventType, EventModel, MetaEventModel

logger = logging.getLogger(__name__)


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
        # TODO: resurface explicitly to the user which parts of the path_event_log gets created

    def __iter__(self):
        paths_str = map(str, self.path_event_log.rglob("*ndjson"))
        for event_log_filename in sorted(paths_str):
            with open(event_log_filename, "rt", encoding="utf-8") as f:
                for event_line in f:
                    yield json.loads(event_line)


class InfraBlobStore(InfraIO):
    def __init__(self, archive_root):
        super().__init__(archive_root)
        self.blob_hash_prefix = "sha256:"
        self.blobs_path = os.path.join(self.root_path, "blobs", "sha256")
        # TODO: resurface explicitly to the user which parts of the blobs path gets created

    def create_and_persist_blob(self, content, media_type):
        # TODO: consolidate the "in {}" condition below across whole file
        if media_type in {MediaType.TEXT_MARKDOWN, MediaType.TEXT_PLAIN}:
            binary_content: bytes = self._bin_encode_decode(
                content=content, content_type=media_type, encode_decode="encode"
            )
        else:
            binary_content = content

        # The hash is the ID and determines the storage path
        blob_hash: str = self._get_blob_hash(binary_content)  # sha256:XXXXX

        self._persist_bin_blob(binary_content, blob_hash)
        return blob_hash

    def _get_blob_hash(self, bin_blob):
        return hashlib.sha256(bin_blob).hexdigest()

    def _bin_encode_decode(self, content: Any, content_type: str, encode_decode: str):
        if (
            content_type in {MediaType.TEXT_MARKDOWN, MediaType.TEXT_PLAIN}
            and encode_decode == "encode"
        ):
            return content.encode(encoding="utf-8")
        if (
            content_type in {MediaType.TEXT_MARKDOWN, MediaType.TEXT_PLAIN}
            and encode_decode == "decode"
        ):
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
            logger.debug(f"BLOB FILE WRITTEN TO {file_path}")
        else:
            # TODO: handle the warning below better
            logger.warning(
                "***WARNING*** FILE EXISTS; NOTHING ADDITIONAL WRITTEN IN blobs/"
            )

    def load_bin_blob(self, blob_hash_from_json: str) -> bytes:
        skip = len(self.blob_hash_prefix)
        sha256_hex = blob_hash_from_json[skip:]
        prefix1 = sha256_hex[:2]
        prefix2 = sha256_hex[2:4]
        dir_path = os.path.join(self.blobs_path, prefix1, prefix2)
        file_path = os.path.join(dir_path, sha256_hex)
        with open(file_path, "rb") as f:
            return f.read()

    def blob_resolver(self, blob_hash: str, media_type: MediaType) -> str:
        if media_type != MediaType.TEXT_PLAIN:
            raise NotImplementedError(f"Unsupported media type {media_type}")
        binary_data = self.load_bin_blob(blob_hash)
        return self._bin_encode_decode(binary_data, media_type, "decode")


class Archive:
    def __init__(
        self,
        event_log: InfraEventLog,
        meta_event_log: InfraEventLog,
        blob_store: InfraBlobStore,
    ):
        """An archive to manage the event log, the meta event log and the data

        It is intentional to dissociate blob store instantiation
        from event log instantiation, because on some infrastructure
        the blob store and the event log may live in different locations

        Args:
            event_log (InfraEventLog): The event log
            blob_store (InfraBlobStore): The blob store
            check_integrity (bool, optional): _description_. Defaults to True.
        """
        self.meta_event_log = meta_event_log
        self.event_log = event_log
        self.blob_store = blob_store
        self.last_event_hash_: str | None = None
        self.last_meta_event_hash_: str | None = None
        self.n_meta_events_: int | None = None
        self.nevents_: int | None = None
        # TODO: consolidate the two subsequent method calls
        self.last_event_hash_, self.nevents_ = self.check_archive_integrity(
            self.event_log
        )
        self.last_meta_event_hash_, self.n_meta_events_ = self.check_archive_integrity(
            self.meta_event_log
        )
        logger.warning("ARCHIVE INTEGRITY VERIFIED")
        logger.debug(
            f"THE ARCHIVE HAS {self.nevents_} EVENTS and {self.n_meta_events_} META EVENTS"
        )

    @property
    def root_path(self):
        if self.blob_store.root_path != self.event_log.root_path:
            raise NotImplementedError()
        return self.blob_store.root_path

    def check_archive_integrity(self, event_log) -> Tuple[str, int]:
        # TODO: currently doesn't check public keys against MANIFEST
        # TODO: if unreferenced blobs, at least mention it as a warning...
        # TODO: if dangling meta nodes with lost underlying items, throw an error
        real_prev_hash = None  # for scenario where event log is empty
        ecount = 0
        for ecount, event in enumerate(event_log):
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

        return real_prev_hash, ecount + int(real_prev_hash is not None)

    def verify_blob_on_disk(self, blob_hash):  # TODO: delegate this to InfraBlobStore
        binary_data = self.blob_store.load_bin_blob(blob_hash)
        real_hash = self.blob_store._get_blob_hash(binary_data)
        given = blob_hash[len(self.blob_store.blob_hash_prefix) :]
        return given == real_hash


class ArchiveIndex:
    """Simple class to quickly inspect and browse an archive."""

    def refresh(self):
        logger.debug("**** REFRESH DEBUG")
        logger.debug(f"""
{self.arc.blob_store.root_path=}
{self.arc.event_log.root_path=}
{self.arc.meta_event_log.root_path=}
********
""")
        blob = InfraBlobStore(self.arc.blob_store.root_path)
        elog = InfraEventLog(self.arc.event_log.root_path)
        mlog = InfraEventLog(self.arc.meta_event_log.root_path)
        arc = Archive(elog, mlog, blob)
        return self.__class__(arc)

    def __init__(self, verified_archive: Archive):
        """Create a simple index for the archive.

        Args:
            verified_archive (Archive): The archive is assumed to have been verified
        """
        self.arc = verified_archive
        self.human_to_machine_id_ = None
        self.id_info_ = None
        self.repr_id_to_underlying_id_ = None
        self._build_index()  # side-effect=set previous three attr
        self.machine_to_human_id_ = None
        self.machine_to_human_id_ = {v: k for k, v in self.human_to_machine_id_.items()}
        self.underlying_id_to_repr_id_ = None
        self.underlying_id_to_repr_id_ = {
            v: k for k, v in self.repr_id_to_underlying_id_.items()
        }

    @property
    def last_event_hash_(self):
        return self.arc.last_event_hash_

    @property
    def nevents_(self):
        return self.arc.nevents_

    @property
    def last_meta_event_hash_(self):
        return self.arc.last_meta_event_hash_

    @property
    def n_meta_events_(self):
        return self.arc.n_meta_events_

    def _build_index(self):
        """Build a simple index

        Side effect: sets the following three attr
            self.human_to_machine_id_
            self.id_info_
            self.repr_id_to_underlying_id_
        """

        idmap = {}
        """Apply eX and mX patterns to graph items

        With X an integer growing in chronological order,
        eX denotes a node or edge
        mX denotes a node or edge in the meta network
        """

        id_info = {}  # info about al items in both networks
        meta_to_base_id = {}
        item_count = 0
        logger.debug("...building index looping through events...")
        for event in self.arc.event_log:
            if event["body"]["event_type"] in {
                EventType.CREATE_EDGE.value,
                EventType.CREATE_NODE.value,
            }:
                item_count += 1
                try:
                    item_id = event["body"]["node_id"]
                    is_edge = False
                except KeyError:
                    item_id = event["body"]["edge_id"]
                    is_edge = True
                idmap["e" + str(item_count)] = item_id
                id_info[UUID(item_id)] = {
                    "is_meta": False,
                    "is_edge": is_edge,
                    "author": event["header"]["author"],
                    "tags": set(),  # will get filled when parsing meta events
                    "body": event["body"].copy(),
                }
            logger.debug(f"*** {item_count=}  {item_id=}")

        item_count = 0
        logger.debug("...building index looping through meta events...")
        for meta_event in self.arc.meta_event_log:
            body = meta_event["body"]
            event_type = body["event_type"]
            if event_type in {
                MetaEventType.CREATE_EDGE_TAG.value,
                MetaEventType.CREATE_NODE_TAG.value,
                MetaEventType.CREATE_EDGE_REPRESENTATION.value,
                MetaEventType.CREATE_NODE_REPRESENTATION.value,
                MetaEventType.SET_EDGE_TAG.value,
                MetaEventType.SET_NODE_TAG.value,
            }:
                item_count += 1
                try:
                    item_id = body["node_id"]
                    is_edge = False
                except KeyError:
                    item_id = body["edge_id"]
                    is_edge = True
                idmap["m" + str(item_count)] = item_id

                item_uuid = UUID(item_id)
                id_info[item_uuid] = {
                    "is_meta": True,
                    "is_edge": is_edge,
                    "is_edge_tag": event_type == MetaEventType.CREATE_EDGE_TAG.value,
                    "is_node_tag": event_type == MetaEventType.CREATE_NODE_TAG.value,
                    "is_edge_representation": event_type
                    == MetaEventType.CREATE_EDGE_REPRESENTATION.value,
                    "is_node_representation": event_type
                    == MetaEventType.CREATE_NODE_REPRESENTATION.value,
                    "author": meta_event["header"]["author"],
                    "body": body.copy(),
                }
            if event_type in {
                MetaEventType.CREATE_EDGE_REPRESENTATION.value,
                MetaEventType.CREATE_NODE_REPRESENTATION.value,
            }:
                meta_to_base_id[UUID(body["node_id"])] = UUID(body["underlying_id"])
            if body["event_type"] in {
                MetaEventType.SET_EDGE_TAG.value,
                MetaEventType.SET_NODE_TAG.value,
            }:
                meta_node_id = UUID(body["target_node"])
                underlying_uuid = meta_to_base_id[meta_node_id]
                current_tag_uuid = UUID(body["source_node"])
                id_info[underlying_uuid]["tags"].update({current_tag_uuid})
            logger.debug(f"*** {item_count=}  {item_id=}")
        self.human_to_machine_id_ = idmap
        self.id_info_ = id_info
        self.repr_id_to_underlying_id_ = meta_to_base_id

    def update_id_mappings(self, event: EventModel | MetaEventModel):
        # TODO: Consolidate with self.build_index() to reduce code redundancy
        def get_latest_int(pref):
            if len(self.human_to_machine_id_.keys()):
                return max(
                    map(
                        lambda s: int(s[len(pref) :]) if s.startswith(pref) else 0,
                        self.human_to_machine_id_.keys(),
                    )
                )
            else:
                return 0

        if isinstance(event, EventModel):
            prefix = "e"
        elif isinstance(event, MetaEventModel):
            prefix = "m"
        else:
            raise ValueError("Invalid event type")
        if event.body.event_type in {
            EventType.CREATE_EDGE,
            EventType.CREATE_NODE,
            MetaEventType.CREATE_EDGE_TAG,
            MetaEventType.CREATE_NODE_TAG,
            MetaEventType.CREATE_EDGE_REPRESENTATION,
            MetaEventType.CREATE_NODE_REPRESENTATION,
            MetaEventType.SET_EDGE_TAG,
            MetaEventType.SET_NODE_TAG,
        }:
            try:
                item_id = str(event.body.node_id)
            except AttributeError:
                item_id = str(event.body.edge_id)
            human_id = prefix + str(get_latest_int(prefix) + 1)
            self.human_to_machine_id_[human_id] = item_id
            self.machine_to_human_id_[item_id] = human_id

    def assert_node_is_tag(self, node_id: UUID) -> None:
        assert self.id_info_[node_id]["is_meta"]
        assert (
            self.id_info_[node_id]["is_edge_tag"]
            or self.id_info_[node_id]["is_node_tag"]
        )

    def confirm_tag_authorship(self, pubkey: str, node_id: UUID):
        assert pubkey == self.id_info_[node_id]["author"]
