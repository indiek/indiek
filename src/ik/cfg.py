from dotenv import set_key
import logging

logger = logging.getLogger(__name__)
# TODO: Define string "IK_ARCHIVE_PATH" globally for whole library here


def run(arc_path: str, set_arc_path: str | None, dotenv_path: str):
    logger.warning(f"Original IK_ARCHIVE_PATH={arc_path}")
    if set_arc_path:
        # TODO: see if the single-quoting of str from set_key can be controlled
        set_key(dotenv_path, "IK_ARCHIVE_PATH", set_arc_path)
        logger.warning(f"New IK_ARCHIVE_PATH={set_arc_path}")
