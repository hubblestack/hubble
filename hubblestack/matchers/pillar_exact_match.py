# -*- coding: utf-8 -*-
"""
This is the default pillar exact matcher.
"""

import logging

import hubblestack.utils.data  # pylint: disable=3rd-party-module-not-gated

log = logging.getLogger(__name__)


def match(tgt, delimiter=":", opts=None):
    """
    Reads in the pillar match, no globbing, no PCRE
    """
    if not opts:
        opts = __opts__
    log.debug("pillar target: %s", tgt)
    if delimiter not in tgt:
        log.error(
            "Got insufficient arguments for pillar match " "statement from master"
        )
        return False

    if "pillar" in opts:
        pillar = opts["pillar"]
    elif "ext_pillar" in opts:
        log.info("No pillar found, fallback to ext_pillar")
        pillar = opts["ext_pillar"]

    return hubblestack.utils.data.subdict_match(
        pillar, tgt, delimiter=delimiter, exact_match=True
    )
