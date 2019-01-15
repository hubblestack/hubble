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


def filter_dict(starting_dict=None, filter_values=False, update_chained=True, chained=None, **kwargs):
    '''
    Given a target dictionary, filter it and return the result.

    By default, ``chained`` will have ``.update()`` called on it
    with ``starting_dict`` as the argument.
    Set ``update_chained`` to False to ignore ``starting_dict``.

    By default, the filtering will be done on keys.
    Set ``filter_values`` to True to filter by values.

    The first return value (status) will be True if the filtering is successful, and
    False othewise. The second argument will be the filtered dictionary.

    ``kwargs`` is a dictionary mapping comparison types to values to compare against.
    '''
    if update_chained:
        if starting_dict:
            chained.update(starting_dict)
    ret = _filter_dict(chained, filter_values, **kwargs)
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


def filter_seq(starting_seq=None, extend_chained=True, chained=None, **kwargs):
    '''
    Given a target sequence, filter it and return the result.

    By default, ``chained`` will have ``.extend()`` or ``.update()`` or ``.format()``
    called on it with ``starting_seq`` as the only argument. Set ``extend_chained`` to False
    to ignore ``starting_seq``.

    The first return value (status) will be True if the filtering is successful, and
    False othewise. The second argument will be the filtered sequence.

    ``kwargs`` is a dictionary mapping comparison types to values to compare against.
    '''
    if extend_chained:
        try:
            if starting_seq and isinstance(chained, set):
                chained.update(starting_seq)
            elif starting_seq and isinstance(chained, list):
                chained.extend(starting_seq)
            elif starting_seq and isinstance(chained, str):
                chained.format(starting_seq)
        except (AttributeError, TypeError) as exc:
            raise ArgumentValueError(str(exc))
    ret = _filter(seq=chained, **kwargs)
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
    for comp, value in kwargs.iteritems():
        ret = [x for x in seq if _compare(comp, x, value)]

    return ret


def get_index(index=0, starting_list=None, extend_chained=True, chained=None):
    '''
    Given a list list, return the item found at ``index``.

    By default, ``chained`` will have ``.extend()`` called on it with
    ``starting_list`` as the only argument.

    The first return value (status) will be True if the return was successful, and
    False othewise. The second argument will be the requested list element.

    ``extend_chained`` is set to True when ``chained`` should be extended with ``starting_list``.
    If set to False, ``starting_list`` is ignored.

    '''
    if extend_chained:
        if starting_list:
            chained.extend(starting_list)
    try:
        ret = chained[index]
    except IndexError:
        log.error('List index out of range {}'.format(index))
        return False, None
    status = bool(ret)

    return status, ret


def get_key(key, starting_dict=None, update_chained=True, chained=None):
    '''
    Given a dictionary, return an element by ``key``.

    By default, ``chained`` will have ``.update()`` called on it with
    ``starting_dict`` as the only argument. Set ``extend_chained`` to False
    to ignore ``starting_dict``.

    The first return value (status) will be True if the key is found, and
    False othewise. The second argument will be the value found by the key or
    None if the key is not present in the dictionary.
    '''
    if update_chained:
        chained.update(starting_dict)
    try:
        ret = chained[key]
    except KeyError:
        log.error("Key not found: {}".format(key))
        return False, None
    status = bool(ret)

    return status, ret


def join(words=None, sep='', extend_chained=True, chained=None):
    '''
    Given a list of strings, join them into a string, using ``sep`` as delimiter.

    By default, ``chained`` will have ``.extend()`` called on it with
    ``words`` as the only argument.

    The first return value (status) will be True if the join was successful, and
    False othewise. The second argument will be the output of the ``join``
    command.

    ``extend_chained`` is set to True when ``chained`` should be extended with ``words``.
    If set to False, ``words`` is ignored.
    '''
    if extend_chained:
        if words:
            chained.extend(words)
    try:
        ret = sep.join(chained)
    except (TypeError, AttributeError):
        log.error("Invalid arguments type")
        ret = None
    status = bool(ret)

    return status, ret


def sort(seq=None, desc=False, lexico=False, extend_chained=True, chained=None):
    '''
    Given a target sequence, sort it and return the sorted result.

    By default, ``chained`` will have ``.extend()`` or ``.update()`` or ``.format()``
    called on it with ``seq`` as the only argument. Set ``extend_chained`` to False
    to ignore ``seq``.

    The first return value (status) will be True if the sort is successful, and
    False othewise. The second argument will be the sorted sequence.
    '''
    if extend_chained:
        try:
            if seq and isinstance(chained, (dict, set)):
                chained.update(seq)
            elif seq and isinstance(chained, list):
                chained.extend(seq)
            elif seq and isinstance(chained, str):
                chained.format(seq)
        except (AttributeError, TypeError):
            log.error("Invalid arguments type")
            return False, None
    ret = _sort(chained, desc, lexico)
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


def dict_to_list(starting_dict=None, update_chained=True, chained=None):
    '''
    Given a target dictionary, convert it to a list of (key, value) tuples.

    By default, ``chained`` will have ``.update()`` called on it with
    ``starting_dict`` as the only argument.
    Set ``update_chained`` to False to ignore ``starting_dict``.

    The first return value (status) will be True if the conversion is successful,
    and False othewise. The second argument will be the list of tuples.
    '''
    if update_chained:
        if starting_dict:
            chained.update(starting_dict)
    ret = [(key, value) for key, value in chained.iteritems()]
    status = bool(ret)

    return status, ret


def dict_convert_none(starting_seq=None, extend_chained=True, chained=None):
    '''
    Given a target sequence, look for dictionary keys that have empty string values and replace them with None

    By default, ``chained`` will have ``.extend()`` or  ``.update()``  called on it with
    ``starting_seq`` as the only argument. Set ``extend_chained`` to False to ignore ``starting_seq``.

    The first return value (status) will be True if the replacing is successful, and
    False othewise. The second argument will be the updated sequence.
    '''
    if extend_chained:
        try:
            if starting_seq and isinstance(chained, (set, dict)):
                chained.update(starting_seq)
            elif starting_seq and isinstance(chained, list):
                chained.extend(starting_seq)
        except (AttributeError, TypeError) as exc:
            raise ArgumentValueError(str(exc))
    if isinstance(chained, dict):
        ret = _dict_convert_none(chained)
    else:
        ret = _seq_convert_none(chained)
    status = bool(ret)

    return status, ret


def _dict_convert_none(dictionary):
    '''
    Look for keys that have values of empty strings and convert them to values of None.
    It recursively looks for nested dictionaries and sterilizes those too

    dictionary
        The input dict to sterilize
    '''
    updated_dict = {}
    for key, value in dictionary.iteritems():
        if value == '':
            updated_dict[key] = None
        elif isinstance(value, dict):
            updated_dict[key] = _dict_convert_none(value)
        elif isinstance(value, (list, set)):
            updated_dict[key] = _seq_convert_none(value)
        else:
            updated_dict[key] = value

    return updated_dict


def _seq_convert_none(seq):
    '''
    Go over a sequence and look for dictionary keys that have values of empty strings
    and convert them to values of None.
    It recursively looks for nested sequences and sterilizes those too

    seq
        The input sequence to sterilize
    '''
    updated_seq = []
    for element in seq:
        if isinstance(element, dict):
            updated_seq.append(_dict_convert_none(element))
        elif isinstance(element, (list, set)):
            updated_seq.append(_seq_convert_none(element))
        else:
            updated_seq.append(element)

    return updated_seq


def dict_remove_none(starting_seq=None, extend_chained=True, chained=None):
    '''
    Given a target sequence, look for dictionary keys that have values of None and remove those keys.

    By default, ``chained`` will have ``.extend()`` or ``.update()`` called on it with
    ``starting_seq`` as the only argument. Set ``extend_chained`` to False to ignore ``starting_seq``.

    The first return value (status) will be True if the sterilizing is successful, and False otherwise.
    The second argument will be the sterilized sequence.
    '''
    if extend_chained:
        try:
            if starting_seq and isinstance(chained, (set, dict)):
                chained.update(starting_seq)
            elif starting_seq and isinstance(chained, list):
                chained.extend(starting_seq)
        except (AttributeError, TypeError) as exc:
            raise ArgumentValueError(str(exc))
    if isinstance(chained, dict):
        ret = _sterilize_dict(chained)
    else:
        ret = _sterilize_seq(chained)
    status = bool(ret)

    return status, ret


def _sterilize_dict(dictionary):
    '''
    Sterilize a dictionary by removing the keys that have values of None.
    It recursively looks for nested dictionaries and sterilizes those too.

    dictionary
        The input dict to sterilize
    '''
    updated_dict = {}
    for key, value in dictionary.iteritems():
        if isinstance(value, dict):
            updated_dict[key] = _sterilize_dict(value)
        elif isinstance(value, (set, list)):
            updated_dict[key] = _sterilize_seq(value)
        elif value is not None:
            updated_dict[key] = value

    return updated_dict


def _sterilize_seq(seq):
    '''
    Sterilize a sequence by looking for dictionary keys that have values of None and removing them.
    It recursively looks for nested sequences and sterilizes those too.

    seq
        The input sequence to sterilize
    '''
    updated_seq = []
    for element in seq:
        if isinstance(element, dict):
            updated_seq.append(_sterilize_dict(element))
        elif isinstance(element, (list, set)):
            updated_seq.append(_sterilize_seq(element))
        else:
            updated_seq.append(element)

    return updated_seq