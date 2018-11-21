# -*- encoding: utf-8 -*-
'''
Flexible Data Gathering: get index
=============================

This fdg module allows returning an item from a list found at a certain index
'''
from __future__ import absolute_import

from salt.exceptions import ArgumentValueError


def get_index(lst, idx=0, get_last=False, append_chained=True, chained=None):
    '''
    Given a list ``lst``, return the item found at ``idx``.

    By default, the ``lst`` will have ``.extend()`` called on it with
    ``chained`` as the only argument.

    The first return value (status) will be True if the return was successful, and
    False othewise. The second argument will be the requested list element.

    ``append_chained`` is set to True when ``lst`` should be extended with ``chained``.
    If set to False, chained is ignored.

    ``get_last`` is used when the last element is requested; ``idx`` is overwritten.
    '''
    if append_chained:
        if chained:
            lst.extend(chained)
    ret = _get_index(lst, idx, get_last)
    status = bool(ret)
    return status, ret


def _get_index(lst,
               idx,
               get_last):
    '''
    Return the element found at index ``idx`` in the list ``lst`` or the last element if
    ``get_last`` is set to True.

    lst
        The input list.

    idx
        The index.

    get_last
        Set to True when the last element is requested.
    '''
    if get_last:
        idx = len(lst) - 1
    try:
        ret = lst[idx]
    except IndexError as exc:
        raise ArgumentValueError(str(exc))

    return ret
