# -*- encoding: utf-8 -*-
'''
Flexible Data Gathering: get_key
=============================

This fdg module allows returning an element from a dictionary
'''
from __future__ import absolute_import


def get_key(dictionary, key, extend_chained=True, chained=None):
    '''
    Given a ``dictionary``, return an element by ``key``.

    By default, the ``dictionary`` will have ``.update()`` called on it with
    ``chained`` as the only argument. Set ``extend_chained`` to False
    to ignore ``chained``.

    The first return value (status) will be True if the key is found, and
    False othewise. The second argument will be the value found by the key or
    None if the key is not present in the dictionary.
    '''
    if extend_chained:
        if chained:
            dictionary.update(chained)
    try:
        ret = dictionary[key]
    except KeyError:
        ret = None
    status = bool(ret)

    return status, ret
