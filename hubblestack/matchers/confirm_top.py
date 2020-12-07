# -*- coding: utf-8 -*-
"""
The matcher subsystem needs a function called 'confirm_top', which
takes the data passed to a top file environment and determines if that
data matches this minion.
"""
import logging

import hubblestack.loader

log = logging.getLogger(__file__)


def confirm_top(match, data, nodegroups=None):
    """
    Takes the data passed to a top file environment and determines if the
    data matches this minion
    """
    matcher = "compound"
    if not data:
        log.error("Received bad data when setting the match from the top " "file")
        return False
    for item in data:
        if isinstance(item, dict):
            if "match" in item:
                matcher = item["match"]

    matchers = hubblestack.loader.matchers(__opts__)
    funcname = matcher + "_match.match"
    if matcher == "nodegroup":
        return matchers[funcname](match, nodegroups)
    else:
        m = matchers[funcname]
        return m(match)
