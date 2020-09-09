# -*- coding: utf-8 -*-
"""
The match module allows for match routines to be run and determine target specs
"""
import copy
import logging

import hubblestack.loader


log = logging.getLogger(__name__)


def compound(tgt, minion_id=None):
    """
    Return True if the minion ID matches the given compound target

    minion_id
        Specify the minion ID to match against the target expression

        .. versionadded:: 2014.7.0

    CLI Example:

    .. code-block:: bash

        salt '*' match.compound 'L@cheese,foo and *'
    """
    if minion_id is not None:
        opts = copy.copy(__opts__)
        if not isinstance(minion_id, str):
            minion_id = str(minion_id)
        opts["id"] = minion_id
    else:
        opts = __opts__
    matchers = hubblestack.loader.matchers(opts)
    try:
        return matchers["compound_match.match"](tgt)
    except Exception as exc:  # pylint: disable=broad-except
        log.exception(exc)
        return False
