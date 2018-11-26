# -*- encoding: utf-8 -*-
'''
Flexible Data Gathering: filter
=============================

This fdg module allows filtering certain values in a sequence
'''
from __future__ import absolute_import

from salt.exceptions import ArgumentValueError


def filter_seq(seq, extend_chained=True, chained=None, **kwargs):
    '''
    Given a target sequence ``seq``, filter it and return the result.

    By default, the ``seq`` will have ``.extend()`` or ``.update()`` or ``.format()``
    called on it with ``chained`` as the only argument. Set ``extend_chained`` to False
    to ignore ``chained``.

    The first return value (status) will be True if the filtering is successful, and
    False othewise. The second argument will be the filtered sequence.

    ``kwargs`` is a dictionary mapping comparison types to values to compare against.
    '''
    if extend_chained:
        try:
            if chained and isinstance(seq, set):
                seq.update(chained)
            elif chained and isinstance(seq, list):
                seq.extend(chained)
            elif chained and isinstance(seq, str):
                seq.format(chained)
        except (AttributeError, TypeError) as exc:
            raise ArgumentValueError(str(exc))
    ret = _filter(seq, **kwargs)
    status = bool(ret)
    return status, ret


def _filter(seq,
            **kwargs):
    '''
    Filter a sequence.

    seq
        The input sequence to be filtered.

    kwargs
        A dict of (comparison_type, value) pairs that dictate the type of filtering
        where comparison_type can be [gt, lt, eq, ne, ge, le].
        For e.g. for ``seq`` = [1, 2, 3, 4, 5] ``kwargs``={le: 4, gt: 1, ne: 2}
        the function outputs [3, 4] - values less than or equal to 4, greater than 1,
        not equal to 2.
    '''
    ret = seq
    for comp, value in kwargs.iteritems():
        ret = [x for x in ret if _compare(comp, x, value)]
    return ret


def _compare(comp, val1, val2):
    '''
    Function that compares two values.

    comp
        The type of comparison that should be applied.
        Can have values from [gt, lt, ge, le, eq, ne].
        For e.g. "gt" stands for "greater than"
    '''
    if comp == "gt":
        return val1 > val2
    if comp == "ge":
        return val1 >= val2
    if comp == "lt":
        return val1 < val2
    if comp == "le":
        return val1 <= val2
    if comp == "eq":
        return val1 == val2
    if comp == "ne":
        return val1 != val2

    raise ArgumentValueError("Invalid argument '{}' should be in [gt, ge, lt, le, eq, ne]".format(comp))
