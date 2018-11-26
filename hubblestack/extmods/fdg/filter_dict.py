# -*- encoding: utf-8 -*-
'''
Flexible Data Gathering: filter
=============================

This fdg module allows filtering certain values in a dictionary
'''
from __future__ import absolute_import

from salt.exceptions import ArgumentValueError


def filter_dict(dct, filter_values=False, extend_chained=True, chained=None, **kwargs):
    '''
    Given a target dict ``dct``, filter it and return the result.

    By default, the ``dct`` will have ``.update()`` called on it
    with ``chained`` as the only argument.
    Set ``extend_chained`` to False to ignore ``chained``.

    By default, the filtering will be done on keys.
    Set ``filter_values`` to True to filter by values.

    The first return value (status) will be True if the filtering is successful, and
    False othewise. The second argument will be the filtered dictionary.


    ``kwargs`` is a dictionary mapping comparison types to values to compare against.
    '''
    if extend_chained:
        if chained:
            dct.update(chained)
    ret = _filter_dict(dct, filter_values, **kwargs)
    status = bool(ret)
    return status, ret


def _filter_dict(dct,
            filter_values,
            **kwargs):
    '''
    Filter a dictionary.

    dct
        The input dictionary to be filtered.

    filter_values
        Indicate if the function should filter the values instead of keys.

    kwargs
        A dict of (comparison_type, value) pairs that dictate the type of filtering
        where comparison_type can be [gt, lt, eq, ne, ge, le].
        For e.g. for ``dct`` = {1: 'a', 2: 'b', 3: 'c', 4: 'd', 5: 'e'}
                      ``kwargs``={le: 4, gt: 1, ne: 2}
        the function outputs {3: 'c', 4: 'd'} - key values less than or equal to 4, greater than 1,
        not equal to 2.
    '''
    ret = dct
    for comp, value in kwargs.iteritems():
        ret = {key: val for key, val in ret.iteritems()
               if (filter_values and _compare(comp, val, value)) or

               (not filter_values and _compare(comp, key, value))}

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
