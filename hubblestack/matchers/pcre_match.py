# -*- coding: utf-8 -*-
"""
This is the default pcre matcher.
"""
import re


def match(tgt, opts=None):
    """
    Returns true if the passed pcre regex matches
    """
    if not opts:
        return bool(re.match(tgt, __opts__["id"]))
    else:
        return bool(re.match(tgt, opts["id"]))
