# -*- encoding: utf-8 -*-
'''
Flexible Data Gathering: sort
=============================

This fdg module allows sorting a sequence
'''
from __future__ import absolute_import

from salt.exceptions import ArgumentValueError


def sort(seq, desc=False, lexico=False, extend_chained=True, chained=None):
    '''
    Given a target sequence ``seq``, sort it and return the sorted result.

    By default, the ``seq`` will have ``.extend()`` or ``.update()`` or ``.format()``
    called on it with ``chained`` as the only argument. Set ``extend_chained`` to False
    to ignore ``chained``.

    The first return value (status) will be True if the sort is successful, and
    False othewise. The second argument will be the sorted sequence.
    '''
    if extend_chained:
        try:
            if chained and isinstance(seq, (dict, set)):
                seq.update(chained)
            elif chained and isinstance(seq, list):
                seq.extend(chained)
            elif chained and isinstance(seq, str):
                seq.format(chained)
        except (AttributeError, TypeError) as exc:
            raise ArgumentValueError(str(exc))
    ret = _sort(seq, desc, lexico)
    status = bool(ret)
    return status, ret


def _sort(seq,
          desc,
          lexico):
    '''
    Sort a sequence.

    seq
        The input sequence to be sorted.

    desc
        Set to True if the sorting should be in descending order.

    lexico
        Set to True if the sorting thould be in lexicographical order.
    '''
    ret = []
    key = None
    if lexico:
        key = str.lower
    ret = sorted(seq, reverse=desc, key=key)
    return ret
