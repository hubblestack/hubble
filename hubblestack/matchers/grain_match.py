# -*- coding: utf-8 -*-
"""
This is the default grains matcher function.
"""

import logging

import hubblestack.utils.data  # pylint: disable=3rd-party-module-not-gated
from hubblestack.defaults import (  # pylint: disable=3rd-party-module-not-gated
    DEFAULT_TARGET_DELIM,
)

log = logging.getLogger(__name__)


def match(tgt, delimiter=DEFAULT_TARGET_DELIM, opts=None):
    """
    Reads in the grains glob match
    """
    if not opts:
        opts = __opts__

    log.debug("grains target: %s", tgt)
    if delimiter not in tgt:
        log.error(
            "Got insufficient arguments for grains match " "statement from master"
        )
        return False

    return hubblestack.utils.data.subdict_match(opts["grains"], tgt, delimiter=delimiter)
