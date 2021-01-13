# -*- coding: utf-8 -*-
"""
Common functions for managing mounts
"""

# Import python libs
import logging
import os

# Import Hubble libs
import hubblestack.utils.files
import hubblestack.utils.stringutils
import hubblestack.utils.versions
import hubblestack.utils.yaml

log = logging.getLogger(__name__)


def _read_file(path):
    """
    Reads and returns the contents of a text file
    """
    try:
        with hubblestack.utils.files.fopen(path, "rb") as contents:
            return hubblestack.utils.yaml.safe_load(contents)
    except (OSError, IOError):
        return {}


def get_cache(opts):
    """
    Return the mount cache file location.
    """
    return os.path.join(opts["cachedir"], "mounts")


def read_cache(opts):
    """
    Write the mount cache file.
    """
    cache_file = get_cache(opts)
    return _read_file(cache_file)


def write_cache(cache, opts):
    """
    Write the mount cache file.
    """
    cache_file = get_cache(opts)

    try:
        _cache = hubblestack.utils.stringutils.to_bytes(hubblestack.utils.yaml.safe_dump(cache))
        with hubblestack.utils.files.fopen(cache_file, "wb+") as fp_:
            fp_.write(_cache)
        return True
    except (IOError, OSError):
        log.error("Failed to cache mounts", exc_info=True)
        return False
