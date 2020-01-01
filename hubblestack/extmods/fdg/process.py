# -*- encoding: utf-8 -*-
"""
Flexible Data Gathering: data processing
=============================

This module primarily processes and properly format
the data outputted by a module to serve it to another module.
"""


import logging
import re

from salt.exceptions import ArgumentValueError
from hubblestack.utils.encoding import encode_base64 as utils_encode_base64

log = logging.getLogger(__name__)


def filter_dict(starting_dict=None, filter_values=False, update_chained=True,
                chained=None, chained_status=None, **kwargs):
    """
    Given a target dictionary, filter it and return the result.

    By default, ``chained`` will have ``.update()`` called on it
    with ``starting_dict`` as the argument.
    Set ``update_chained`` to False to ignore ``starting_dict``.

    By default, the filtering will be done on keys.
    Set ``filter_values`` to True to filter by values.

    The first return value (status) will be True if the filtering is successful, and
    False othewise. The second argument will be the filtered dictionary.

    ``kwargs`` is a dictionary mapping comparison types to values to compare against.

    chained_status
        The status returned by the chained method.
    """
    try:
        if update_chained:
            if starting_dict:
                chained.update(starting_dict)
    except (AttributeError, TypeError, ValueError):
        log.error('Invalid argument type - dict required', exc_info=True)
        return False, None
    ret = _filter_dict(chained, filter_values, kwargs)
    status = bool(ret)

    return status, ret


def _filter_dict(dct,
                 filter_values,
                 filter_rules):
    """
    Filter a dictionary.

    dct
        The input dictionary to be filtered.

    filter_values
        ``True`` if the function should filter the values instead of keys,
        ``False`` otherwise.

    filter_rules
        A dict of (comparison_type, value) pairs that dictate the type of filtering
        where comparison_type can be [gt, lt, eq, ne, ge, le].
        For e.g. for ``dct`` = {1: 'a', 2: 'b', 3: 'c', 4: 'd', 5: 'e'}
                      ``kwargs``={le: 4, gt: 1, ne: 2}
        the function outputs {3: 'c', 4: 'd'} - key values less than or equal to 4, greater than 1,
        not equal to 2.
    """
    ret = dct
    for comp, value in filter_rules.items():
        try:
            ret = {key: val for key, val in ret.items()
                   if (filter_values and _compare(comp, val, value)) or
                   (not filter_values and _compare(comp, key, value))}
        except ArgumentValueError:
            return None

    return ret


def _compare(comp, val1, val2):
    """
    Function that compares two values.

    comp
        The type of comparison that should be applied.
        Can have values from [gt, lt, ge, le, eq, ne].
        For e.g. "gt" stands for "greater than"
    """
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

    log.error("Invalid argument '%s' - should be in [gt, ge, lt, le, eq, ne]", comp)
    raise ArgumentValueError


def filter_seq(starting_seq=None, extend_chained=True, chained=None, chained_status=None, **kwargs):
    """
    Given a target sequence, filter it and return the result.

    By default, ``chained`` will have ``.extend()`` or ``.update()`` or ``.format()``
    called on it with ``starting_seq`` as the only argument. Set ``extend_chained`` to False
    to ignore ``starting_seq``.

    The first return value (status) will be True if the filtering is successful, and
    False othewise. The second argument will be the filtered sequence.

    ``kwargs`` is a dictionary mapping comparison types to values to compare against.
    It can take the following values:
        ge = greater or equal, gt = greater than, lt = lower than, le = lower or equal
        ne = not equal, eq = equal
    Sample module:
        module: process.filter_seq
          kwargs:
            starting_seq: [1, 2, 3, 4, 5]
            ge: 1
            ne: 2
            lt:5
    Outputs: [3, 4]

    chained_status
        Status returned by the chained method.
    """
    if extend_chained:
        try:
            if starting_seq and isinstance(chained, set):
                chained.update(starting_seq)
            elif starting_seq and isinstance(chained, list):
                chained.extend(starting_seq)
            elif starting_seq and isinstance(chained, str):
                chained = starting_seq.format(chained)
            else:
                raise AttributeError
        except (AttributeError, TypeError, ValueError):
            log.error("Invalid argument type", exc_info=True)
            return False, None
    ret = _filter(seq=chained, filter_rules=kwargs)
    status = bool(ret)

    return status, ret


def _filter(seq,
            filter_rules):
    """
    Filter a sequence.

    seq
        The input sequence to be filtered.

    filter_rules
        A dict of (comparison_type, value) pairs that dictate the type of filtering
        where comparison_type can be [gt, lt, eq, ne, ge, le].
        For e.g. for ``seq`` = [1, 2, 3, 4, 5] ``filter_rules``={le: 4, gt: 1, ne: 2}
        the function outputs [3, 4] - values less than or equal to 4, greater than 1,
        not equal to 2.
    """
    if not isinstance(filter_rules, dict):
        log.error("``filter_rules`` should be of type dict")
        return None
    ret = seq
    for comp, value in filter_rules.items():
        try:
            ret = [x for x in ret if _compare(comp, x, value)]
        except ArgumentValueError:
            return None

    return ret


def get_index(index=0, starting_list=None, extend_chained=True, chained=None, chained_status=None):
    """
    Given a list list, return the item found at ``index``.

    By default, ``chained`` will have ``.extend()`` called on it with
    ``starting_list`` as the only argument.

    The first return value (status) will be True if the return was successful, and
    False othewise. The second argument will be the requested list element.

    ``extend_chained`` is set to True when ``chained`` should be extended with ``starting_list``.
    If set to False, ``starting_list`` is ignored.

    chained_status
        Status returned by the chained method.

    """
    if extend_chained:
        if starting_list:
            try:
                chained.extend(starting_list)
            except (AttributeError, TypeError):
                log.error("Invalid argument type", exc_info=True)
                return False, None
    try:
        ret = chained[index]
    except IndexError:
        log.error('List index out of range %d', index, exc_info=True)
        return False, None
    except TypeError:
        log.error('Arguments should be of type list', exc_info=True)
        return False, None
    status = bool(ret)

    return status, ret


def get_key(key, starting_dict=None, update_chained=True, chained=None, chained_status=None):
    """
    Given a dictionary, return an element by ``key``.

    By default, ``chained`` will have ``.update()`` called on it with
    ``starting_dict`` as the only argument. Set ``extend_chained`` to False
    to ignore ``starting_dict``.

    The first return value (status) will be True if the key is found, and
    False othewise. The second argument will be the value found by the key or
    None if the key is not present in the dictionary.

    chained_status
        Status returned by the chained method.
    """
    if update_chained:
        if starting_dict:
            try:
                chained.update(starting_dict)
            except (TypeError, ValueError):
                log.error("Arguments should be of type dict.", exc_info=True)
                return False, None
    try:
        ret = chained[key]
    except KeyError:
        log.error("Key not found: %s", key, exc_info=True)
        return False, None
    except TypeError:
        log.error("Arguments should be of type dict.", exc_info=True)
        return False, None
    status = bool(ret)

    return status, ret


def join(words=None, sep='', extend_chained=True, chained=None, chained_status=None):
    """
    Given a list of strings, join them into a string, using ``sep`` as delimiter.

    By default, ``chained`` will have ``.extend()`` called on it with
    ``words`` as the only argument.

    The first return value (status) will be True if the join was successful, and
    False othewise. The second argument will be the output of the ``join``
    command.

    ``extend_chained`` is set to True when ``chained`` should be extended with ``words``.
    If set to False, ``words`` is ignored.

    chained_status
        Status returned by the chained method.
    """
    if extend_chained:
        if words:
            try:
                chained.extend(words)
            except (AttributeError, TypeError):
                log.error("Arguments should be of type list.", exc_info=True)
                return False, None
    try:
        ret = sep.join(chained)
    except (TypeError, AttributeError):
        log.error("Invalid arguments type.", exc_info=True)
        ret = None
    status = bool(ret)

    return status, ret


def sort(seq=None, desc=False, lexico=False, extend_chained=True,
         chained=None, chained_status=None):
    """
    Given a target sequence, sort it and return the sorted result.

    By default, ``chained`` will have ``.extend()`` or ``.update()`` or ``.format()``
    called on it with ``seq`` as the only argument. Set ``extend_chained`` to False
    to ignore ``seq``.

    The first return value (status) will be True if the sort is successful, and
    False othewise. The second argument will be the sorted sequence.

    chained_status
        Status returned by the chained method.
    """
    if extend_chained:
        try:
            if seq and isinstance(chained, (dict, set)):
                chained.update(seq)
            elif seq and isinstance(chained, list):
                chained.extend(seq)
            elif seq and isinstance(chained, str):
                chained = seq.format(chained)
        except (AttributeError, TypeError, ValueError):
            log.error("Invalid arguments type.", exc_info=True)
            return False, None
    ret = _sort(chained, desc, lexico)
    status = bool(ret)

    return status, ret


def _sort(seq,
          desc,
          lexico):
    """
    Sort a sequence.

    seq
        The input sequence to be sorted.

    desc
        Set to True if the sorting should be in descending order.

    lexico
        Set to True if the sorting thould be in lexicographical order.
    """
    key = None
    if lexico:
        key = str.lower
    try:
        ret = sorted(seq, reverse=desc, key=key)
    except TypeError:
        log.error("Invalid argument type.", exc_info=True)
        return None

    return ret


def split(phrase, sep=None, regex=False, format_chained=True, chained=None, chained_status=None):
    """
    Given a ``phrase`` string, split it into a list of words by a ``sep`` delimiter.

    By default, the ``phrase`` will have ``.format()`` called on it with
    ``chained`` as the only argument. (So, use ``{0}`` in your phrase to
    substitute the chained value.) If you want to avoid having to escape
    curly braces, set ``format_chained=False``.

    The first return value (status) will be True if the delimiter is found and
    the splitting is successful, and False othewise. The second argument will be
    the output of the ``split`` command.

    ``regex`` will be set to True if ``sep`` is a regex instead of a pattern.

    chained_status
        Status returned by the chained method.
    """
    if format_chained:
        if chained:
            try:
                phrase = phrase.format(chained)
            except AttributeError:
                log.error("Invalid attributes type.", exc_info=True)
                return False, None
    ret = _split(phrase, sep, regex)
    status = bool(ret) and len(ret) > 1

    return status, ret


def _split(phrase,
           sep,
           regex):
    """
    Run the split command on the phrase using ``sep`` as a delimiter or regex.

    phrase
        The string to be split.

    sep
        Separator to split by. It can either be a delimiter or a regex.
        If it's None it will split by whitespace.

    regex
        Set to True if ``sep`` should be treated as a regex instead of a delimiter.
    """
    try:
        if regex:
            ret = re.split(sep, phrase)
        else:
            ret = phrase.split(sep)
    except (AttributeError, TypeError):
        log.error("Invalid argument type.", exc_info=True)
        return None

    return ret


def dict_to_list(starting_dict=None, update_chained=True, chained=None, chained_status=None):
    """
    Given a target dictionary, convert it to a list of (key, value) tuples.

    By default, ``chained`` will have ``.update()`` called on it with
    ``starting_dict`` as the only argument.
    Set ``update_chained`` to False to ignore ``starting_dict``.

    The first return value (status) will be True if the conversion is successful,
    and False othewise. The second argument will be the list of tuples.

    chained_status
        Status returned by the chained method.
    """
    if update_chained:
        if starting_dict:
            try:
                chained.update(starting_dict)
            except (AttributeError, ValueError, TypeError):
                log.error("Invalid arguments type.", exc_info=True)
                return False, None
    ret = [(key, value) for key, value in chained.items()]
    status = bool(ret)

    return status, ret


def dict_convert_none(starting_seq=None, extend_chained=True, chained=None, chained_status=None):
    """
    Given a target sequence, look for dictionary keys that have empty string values
     and replace them with None.

    By default, ``chained`` will have ``.extend()`` or  ``.update()``  called on it with
    ``starting_seq`` as the only argument.
    Set ``extend_chained`` to False to ignore ``starting_seq``.

    The first return value (status) will be True if the replacing is successful, and
    False othewise. The second argument will be the updated sequence.

    chained_status
        Status returned by the chained method.
    """
    if extend_chained:
        try:
            if starting_seq and isinstance(chained, (set, dict)):
                chained.update(starting_seq)
            elif starting_seq and isinstance(chained, list):
                chained.extend(starting_seq)
        except (AttributeError, TypeError, ValueError):
            log.error("Invalid type of arguments", exc_info=True)
            return False, None
    if isinstance(chained, dict):
        ret = _dict_convert_none(chained)
    elif isinstance(chained, (set, list, tuple)):
        ret = _seq_convert_none(chained)
    else:
        log.error("Invalid arguments type - dict or sequence expected")
        ret = None
    status = bool(ret)

    return status, ret


def _dict_convert_none(dictionary):
    """
    Look for keys that have values of empty strings and convert them to values of None.
    It recursively looks for nested dictionaries and sterilizes those too

    dictionary
        The input dict to sterilize
    """
    if not isinstance(dictionary, dict):
        log.error("Invalid argument type - should be dict")
        return None
    updated_dict = {}
    for key, value in dictionary.items():
        if value == '':
            updated_dict[key] = None
        elif isinstance(value, dict):
            updated_dict[key] = _dict_convert_none(value)
        elif isinstance(value, (list, set, tuple)):
            updated_dict[key] = _seq_convert_none(value)
        else:
            updated_dict[key] = value

    return updated_dict


def _seq_convert_none(seq):
    """
    Go over a sequence and look for dictionary keys that have values of empty strings
    and convert them to values of None.
    It recursively looks for nested sequences and sterilizes those too

    seq
        The input sequence to sterilize
    """
    if not isinstance(seq, (list, set, tuple)):
        log.error("Invalid argument type - list set or tuple expected")
        return None
    updated_seq = []
    for element in seq:
        if isinstance(element, dict):
            updated_seq.append(_dict_convert_none(element))
        elif isinstance(element, (list, set, tuple)):
            updated_seq.append(_seq_convert_none(element))
        else:
            updated_seq.append(element)

    return updated_seq


def print_string(starting_string, format_chained=True, chained=None, chained_status=None):
    """
    Given a string, return it.

    By default, ``starting_string`` will have ``.format()`` called on it
    with ``chained`` as the only argument. (So, use ``{0}`` in your pattern to
    substitute the chained value.) If you want to avoid having to escape curly braces,
    set ``format_chained=False``.

    chained_status
        Status returned by the chained method.

    The first return value (status) will be False only if an error will occur.
    """
    if format_chained:
        try:
            starting_string = starting_string.format(chained)
        except AttributeError:
            log.error("Invalid type for starting_string - has to be string.", exc_info=True)
            return False, None
    if not isinstance(starting_string, str):
        log.error('Invalid arguments - starting_string should be a string')
        return False, None

    return bool(starting_string), starting_string


def dict_remove_none(starting_seq=None, extend_chained=True, chained=None, chained_status=None):
    """
    Given a target sequence, look for dictionary keys that have values of None and remove them.

    By default, ``chained`` will have ``.extend()`` or ``.update()`` called on it with
    ``starting_seq`` as the only argument.
    Set ``extend_chained`` to False to ignore ``starting_seq``.

    chained_status
        Status returned by the chained method.

    The first return value (status) will be True if the sterilizing is successful,
    and False otherwise.
    The second argument will be the sterilized sequence.
    """
    if extend_chained:
        try:
            if starting_seq and isinstance(chained, (set, dict)):
                chained.update(starting_seq)
            elif starting_seq and isinstance(chained, list):
                chained.extend(starting_seq)
        except (AttributeError, TypeError, ValueError):
            log.error("Invalid arguments type", exc_info=True)
            return False, None
    if isinstance(chained, dict):
        ret = _sterilize_dict(chained)
    elif isinstance(chained, (list, set, tuple)):
        ret = _sterilize_seq(chained)
    else:
        log.error("Invalid arguments type - dict, list, set or tuple expected")
        ret = None
    status = bool(ret)

    return status, ret


def _sterilize_dict(dictionary):
    """
    Sterilize a dictionary by removing the keys that have values of None.
    It recursively looks for nested dictionaries and sterilizes those too.

    dictionary
        The input dict to sterilize
    """
    if not isinstance(dictionary, dict):
        log.error("Invalid argument type - should be dict")
        return None
    updated_dict = {}
    for key, value in dictionary.items():
        if isinstance(value, dict):
            updated_dict[key] = _sterilize_dict(value)
        elif isinstance(value, (set, list, tuple)):
            updated_dict[key] = _sterilize_seq(value)
        elif value is not None:
            updated_dict[key] = value

    return updated_dict


def _sterilize_seq(seq):
    """
    Sterilize a sequence by looking for dictionary keys that have values of None and removing them.
    It recursively looks for nested sequences and sterilizes those too.

    seq
        The input sequence to sterilize
    """
    if not isinstance(seq, (list, set, tuple)):
        log.error('Invalid argument type - should be list, set or tuple')
        return None
    updated_seq = []
    for element in seq:
        if isinstance(element, dict):
            updated_seq.append(_sterilize_dict(element))
        elif isinstance(element, (list, set, tuple)):
            updated_seq.append(_sterilize_seq(element))
        else:
            updated_seq.append(element)

    return updated_seq


def nop(format_chained=True, chained=None, chained_status=None):
    """
    This function just returns the chained value. It is a nop/no operation.

    This can be useful if you want to do a pipe_on_true to filter out
    False values -- you can pipe_on_true to process.nop, and stick a
    returner on the nop operation to just return the True values.
    """
    return chained


def encode_base64(starting_string, format_chained=True, chained=None, chained_status=None):
    """
    Given a string, base64 encode it and return it.

    By default, ``starting_string`` will have ``.format()`` called on it
    with ``chained`` as the only argument. (So, use ``{0}`` in your pattern to
    substitute the chained value.) If you want to avoid having to escape curly braces,
    set ``format_chained=False``.

    chained_status
        Status returned by the chained method.

    The first return value (status) will be False only if an error will occur.
    """
    return utils_encode_base64(starting_string, format_chained=format_chained,
                               chained=chained, chained_status=chained_status)
