# -*- encoding: utf-8 -*-
'''
Flexible Data Gathering: data processing
=============================

This module primarily processes and properly format
the data outputted by a module to serve it to another module.
'''
from __future__ import absolute_import
import logging
import re

from salt.exceptions import ArgumentValueError

log = logging.getLogger(__name__)


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
    except IndexError:
        log.error('List index out of range {}'.format(idx))
        return None

    return ret


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
        log.error("Key not found: {}".format(key))
        ret = None
    status = bool(ret)

    return status, ret


def join(words, sep='', append_chained=True, chained=None):
    '''
    Given a list of strings ``words``, join them into a string, using ``sep`` as delimiter.

    By default, the ``words`` will have ``.extend()`` called on it with
    ``chained`` as the only argument.

    The first return value (status) will be True if the join was successful, and
    False othewise. The second argument will be the output of the ``join``
    command.

    ``append_chained`` is set to True when ``words`` should be extended with ``chained``.
    If set to False, chained is ignored.
    '''
    if append_chained:
        if chained:
            words.extend(chained)
    try:
        ret = sep.join(words)
    except (TypeError, AttributeError):
        log.error("Invalid arguments type")
        ret = None
    status = bool(ret)

    return status, ret


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
        except (AttributeError, TypeError):
            log.error("Invalid arguments type")
            return False, None
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


def split(phrase, sep=None, regex=False, format_chained=True, chained=None):
    '''
    Given a ``phrase`` string, split it into a list of words by a ``sep`` delimiter.

    By default, the ``phrase`` will have ``.format()`` called on it with
    ``chained`` as the only argument. (So, use ``{0}`` in your phrase to
    substitute the chained value.) If you want to avoid having to escape
    curly braces, set ``format_chained=False``.

    The first return value (status) will be True if the delimiter is found and
    the splitting is successful, and False othewise. The second argument will be
    the output of the ``split`` command.

    ``regex`` will be set to True if ``sep`` is a regex instead of a pattern.

    '''
    if format_chained:
        phrase = phrase.format(chained)
    ret = _split(phrase, sep, regex)
    status = bool(ret) and len(ret) > 1

    return status, ret


def _split(phrase,
           sep,
           regex):
    '''
    Run the split command on the phrase using ``sep`` as a delimiter or regex.

    phrase
        The string to be split.

    sep
        Separator to split by. It can either be a delimiter or a regex.
        If it's None it will split by whitespace.

    regex
        Set to True if ``sep`` should be treated as a regex instead of a delimiter.
    '''
    ret = []
    if regex:
        ret = re.split(sep, phrase)
    else:
        ret = phrase.split(sep)

    return ret
