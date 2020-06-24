# -*- coding: utf-8 -*-
"""
Add the hubble version to the grains
"""
import logging

from hubblestack import __version__

log = logging.getLogger(__name__)


def hubble_version():
    """
    Add the hubble version to the grains
    """
    return {'hubble_version': __version__}


def hubble_build_metadata():
    """
    Add hubble build metadata to grains
    """
    build_metadata = {}
    try:
        from hubblestack import __buildinfo__
    except ImportError:
        __buildinfo__ = {'build_metadata': 'NOT SET'}
    build_metadata.update(__buildinfo__)

    return {'buildinfo': build_metadata}
