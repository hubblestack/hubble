# -*- coding: utf-8 -*-
"""
This is the default glob matcher function.
"""

import fnmatch


def match(tgt, opts=None):
    """
    Returns true if the passed glob matches the id
    """

    if opts is None:
        opts = __opts__

    minion_id = opts.get("minion_id", opts["id"])

    if not isinstance(tgt, str):
        return False

    return fnmatch.fnmatch(minion_id, tgt)
