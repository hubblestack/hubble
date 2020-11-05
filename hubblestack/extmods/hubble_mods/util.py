# -*- encoding: utf-8 -*-
"""
Module having utility methods for data processing
=================================================

This module primarily processes and properly format
the data outputted by a module to serve it to another module.

All functions in this module are meant to be used in chaining.

Functions supported:
--------------------
- filter_dict
    Given a target dictionary, filter it and return the result.
    
    Arguments supported:
        starting_dict:  (Optional) Starting dictionary
        update_chained: (Default True)
                            If True, ``chained value`` will have ``.update()`` called on it
                            with ``starting_dict`` as the argument.
                            Set ``update_chained`` to False to ignore ``starting_dict``.
        filter_values:  (Default False)
                            By default, the filtering will be done on keys.
                            Set ``filter_values`` to True to filter by values.
        filter_rules:   (Mandatory) is a dictionary mapping comparison types to values 
                            to compare against.
                            It can take the following values:
                                ge = greater or equal, gt = greater than, 
                                lt = lower than, le = lower or equal
                                ne = not equal, eq = equal

- filter_seq
    Given a target sequence, filter it and return the result.

    Arguments supported:
        starting_seq:  (Optional) Starting sequence
        extend_chained:(Optional) (Default True) 
                        If True, update starting_seq with chained value
        filter_rules:  (Mandatory) is a dictionary mapping comparison types to values 
                       to compare against.
                       It can take the following values:
                        ge = greater or equal, gt = greater than, 
                        lt = lower than, le = lower or equal
                        ne = not equal, eq = equal

- get_index
    Given a list, return the item found at ``index``.

    Arguments supported:
        index:          (Mandatory)
                        Index value for which value is needed
        starting_list:  (Optional)
                        Starting list param
        extend_chained: (Default True)
                        By default, ``chained`` will have ``.extend()`` called on it with
                        ``starting_list`` as the only argument.

- get_key
    Given a dictionary, return an element by ``key``.

    Arguments supported:
        key:           (Mandatory)
                        Key value to get
        starting_dict: (Optional)
                        Starting dictionary param
        extend_chained: (Default True)
                        By default, ``chained`` will have ``.update()`` called on it with
                        ``starting_dict`` as the only argument. Set ``extend_chained`` to False
                        to ignore ``starting_dict``.

- join
    Given a list of strings, join them into a string, using ``sep`` as delimiter.

    Arguments supported:
        words:          (Mandatory)
                        List of string
        sep:            (Optional)
                        Separator, Default: ''
        extend_chained: (Default True)
                        By default, ``chained`` will have ``.extend()`` called on it with
                        ``words`` as the only argument.

- dict_to_list
    Given a target dictionary, convert it to a list of (key, value) tuples.

    Arguments supported:
        starting_dict:  (Optional)
                        Initial dictionary
        update_chained: (Default True)
                        By default, ``chained`` will have ``.update()`` called on it with
                        ``starting_dict`` as the only argument.
                        Set ``update_chained`` to False to ignore ``starting_dict``.

- dict_convert_none
    Given a target sequence, look for dictionary keys that have empty string values
    and replace them with None.

    Arguments supported:
        starting_dict:  (Optional)
                        Initial dictionary
        extend_chained: (Default True)
                        By default, ``chained`` will have ``.extend()`` or  ``.update()``  called on it with
                        ``starting_seq`` as the only argument.
                        Set ``extend_chained`` to False to ignore ``starting_seq``.

- print_string
    Given a string, return it.

    Arguments supported:
        starting_string:  (Optional)
                        Initial string
        format_chained: (Default True)
                        By default, ``starting_string`` will have ``.format()`` called on it
                        with ``chained`` as the only argument. (So, use ``{0}`` in your pattern to
                        substitute the chained value.) If you want to avoid having to escape curly braces,
                        set ``format_chained=False``.

- dict_remove_none
    Given a target sequence, look for dictionary keys that have values 
    of None and remove them.

    Arguments supported:
        starting_seq:  (Optional)
                        Initial sequence
        extend_chained: (Default True)
                        By default, ``chained`` will have ``.extend()`` or ``.update()`` called on it with
                        ``starting_seq`` as the only argument.
                        Set ``extend_chained`` to False to ignore ``starting_seq``.

- nop
    This function just returns the chained value. It is a nop/no operation.

    No Argument supported (Only chaining param)

- encode_base64
    Given a string, base64 encode it and return it.

    Arguments supported:
        starting_string:(Optional)
                        Initial string
        format_chained: (Default True)
                        By default, ``starting_string`` will have ``.format()`` called on it
                        with ``chained`` as the only argument. (So, use ``{0}`` in your pattern to
                        substitute the chained value.) If you want to avoid having to escape curly braces,
                        set ``format_chained=False``.

------------------------------------------------
FDG Profile Example for one utility method:

main:
    module: stat
    args:
        path: /abc
    pipe: check

check:
  module: util
    args:
        function: filter_dict
        filter_rules:
            gt: 1
            ne: 3
            le: 4

If chained value is: [1, 2]
Output: [2, 4]
"""

import logging
import re

from salt.exceptions import ArgumentValueError
from hubblestack.utils.encoding import encode_base64 as utils_encode_base64

from hubblestack.extmods.module_runner.runner import Caller
import hubblestack.extmods.module_runner.runner_utils as runner_utils
from hubblestack.utils.hubble_error import HubbleCheckValidationError

log = logging.getLogger(__name__)


def validate_params(block_id, block_dict, extra_args=None):
    """
    Validate all mandatory params required for this module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "Output (can be string/dict/list)", 'status': True},
                  'caller': 'Audit'}

    Raises:
        HubbleCheckValidationError: For any validation error
    """
    log.debug('Module: util Start validating params for check-id: {0}'.format(block_id))

    # fetch required param
    error = {}
    
    # This module is callable from FDG only
    if extra_args.get('caller') == Caller.AUDIT:
        error['util'] = 'Module: util called from AUDIT !!!!'

    function_param = runner_utils.get_param_for_module(block_id, block_dict, 'function')
    if not function_param:
        error['function'] = 'Mandatory parameter: function not found for id: %s' % (block_id)
    elif function_param not in ['filter_dict']:
        error['function'] = 'Unsupported function in util: {0}'.format(function_param)
    else:
        if function_param == 'filter_dict':
            if not runner_utils.get_param_for_module(block_id, block_dict, 'filter_rules'):
                error['filter_rules'] = 'filter_rules required for function: filter_dict'
        elif function_param == 'filter_seq':
            if not runner_utils.get_param_for_module(block_id, block_dict, 'filter_rules'):
                error['filter_rules'] = 'filter_rules required for function: filter_seq'
        elif function_param == 'get_key':
            if not runner_utils.get_param_for_module(block_id, block_dict, 'key'):
                error['key'] = 'key is required for function: get_key'
        elif function_param == 'join':
            if not runner_utils.get_param_for_module(block_id, block_dict, 'words'):
                error['words'] = 'words are required for function: join'
        elif function_param == ['dict_convert_none', 'print_string', 'dict_to_list', 
            'get_index', 'dict_remove_none', 'nop', 'encode_base64']:
            # no mandatory key, mentioned here just for clarity
            pass

    if error:
        raise HubbleCheckValidationError(error)

    log.debug('Validation success for check-id: {0}'.format(block_id))

def execute(block_id, block_dict, extra_args=None):
    """
    Execute the module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "Output (can be string/dict/list)", 'status': True},
                  'caller': 'Audit'}

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing util module for id: {0}'.format(block_id))
    
    function_param = runner_utils.get_param_for_module(block_id, block_dict, 'function')
    if function_param == 'filter_dict':
        return _filter_dict(block_id, block_dict, extra_args)
    elif function_param == 'filter_seq':
        return _filter_seq(block_id, block_dict, extra_args)
    elif function_param == 'get_index':
        return _get_index(block_id, block_dict, extra_args)
    elif function_param == 'get_key':
        return _get_key(block_id, block_dict, extra_args)
    elif function_param == 'join':
        return _join(block_id, block_dict, extra_args)
    elif function_param == 'dict_to_list':
        return _dict_to_list(block_id, block_dict, extra_args)
    elif function_param == 'dict_convert_none':
        return _dict_convert_none(block_id, block_dict, extra_args)
    elif function_param == 'print_string':
        return _print_string(block_id, block_dict, extra_args)
    elif function_param == 'dict_remove_none':
        return _dict_remove_none(block_id, block_dict, extra_args)
    elif function_param == 'nop':
        return _nop(block_id, block_dict, extra_args)
    elif function_param == 'encode_base64':
        return _encode_base64(block_id, block_dict, extra_args)

def _filter_seq(block_id, block_dict, extra_args):
    """
    Given a target sequence, filter it and return the result.

    block_dict:    
        By default, ``chained`` will have ``.extend()`` or ``.update()`` or ``.format()``
        called on it with ``starting_seq`` as the only argument. Set ``extend_chained`` to False
        to ignore ``starting_seq``.

        starting_seq: (Optional) Starting sequence
        extend_chained: (Optional) (Default True) 
                        If True, update starting_seq with chained value
        filter_rules: (Mandatory) is a dictionary mapping comparison types to values 
                      to compare against.
                      It can take the following values:
                        ge = greater or equal, gt = greater than, 
                        lt = lower than, le = lower or equal
                        ne = not equal, eq = equal
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "Output", 'status': True},
                  'caller': 'Audit'}
    """
    chained = runner_utils.get_chained_param(extra_args)

    starting_seq = runner_utils.get_param_for_module(block_id, block_dict, 'starting_seq')
    extend_chained = runner_utils.get_param_for_module(block_id, block_dict, 'extend_chained', True)
    filter_rules = runner_utils.get_param_for_module(block_id, block_dict, 'filter_rules')

    if extend_chained and starting_seq:
        try:
            if isinstance(chained, set):
                chained.update(starting_seq)
            elif isinstance(chained, list):
                chained.extend(starting_seq)
            elif isinstance(chained, str):
                chained = starting_seq.format(chained)
            else:
                raise AttributeError
        except (AttributeError, TypeError, ValueError):
            log.error("Invalid argument type", exc_info=True)
            return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')
    return _filter(block_id, seq=chained, filter_rules=filter_rules)

def _filter(block_id, seq, filter_rules):
    """
    Filter a sequence.
    
    block_id
        Block id

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
        return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')
    ret = seq
    for comp, value in filter_rules.items():
        try:
            ret = [x for x in ret if _compare(comp, x, value)]
        except ArgumentValueError:
            return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')

    return runner_utils.prepare_positive_result_for_module(block_id, ret)

def _filter_dict(block_id, block_dict, extra_args=None):
    """
    Given a target dictionary, filter it and return the result.

    block_id:
        Block id

    block_dict:
        starting_dict:  (Optional) Starting dictionary
        update_chained: (Default True)
                            If True, ``chained value`` will have ``.update()`` called on it
                            with ``starting_dict`` as the argument.
                            Set ``update_chained`` to False to ignore ``starting_dict``.
        filter_values:  (Default False)
                            By default, the filtering will be done on keys.
                            Set ``filter_values`` to True to filter by values.
        filter_rules:   (Mandatory) is a dictionary mapping comparison types to values 
                            to compare against.
                            It can take the following values:
                                ge = greater or equal, gt = greater than, 
                                lt = lower than, le = lower or equal
                                ne = not equal, eq = equal
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "Output", 'status': True},
                  'caller': 'Audit'}
    """
    chained = runner_utils.get_chained_param(extra_args)

    starting_dict = runner_utils.get_param_for_module(block_id, block_dict, 'starting_dict')
    update_chained = runner_utils.get_param_for_module(block_id, block_dict, 'update_chained', True)
    filter_values = runner_utils.get_param_for_module(block_id, block_dict, 'filter_values', False)
    filter_rules = runner_utils.get_param_for_module(block_id, block_dict, 'filter_rules')

    try:
        if update_chained and starting_dict:
            chained.update(starting_dict)
    except (AttributeError, TypeError, ValueError):
        log.error('Invalid argument type - dict required', exc_info=True)
        return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')

    return _filter_dict_helper(block_id, chained, filter_values, filter_rules)

def _filter_dict_helper(block_id, dct, filter_values, filter_rules):
    """
    Filter a dictionary.

    block_id
        Block id

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
            return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')

    return runner_utils.prepare_positive_result_for_module(block_id, ret)

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

def _get_index(block_id, block_dict, extra_args):
    """
    Given a list list, return the item found at ``index``.

    block_id:
        Block id

    block_dict:
        index:         (Mandatory)
                        Index value for which value is needed
        starting_list: (Optional)
                        Starting list param
        extend_chained: (Default True)
                        By default, ``chained`` will have ``.extend()`` called on it with
                        ``starting_list`` as the only argument.

    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "Output", 'status': True},
                  'caller': 'Audit'}

    The first return value (status) will be True if the return was successful, and
    False othewise. The second argument will be the requested list element.

    """
    chained = runner_utils.get_chained_param(extra_args)

    index = runner_utils.get_param_for_module(block_id, block_dict, 'index', 0)
    starting_list = runner_utils.get_param_for_module(block_id, block_dict, 'starting_list')
    extend_chained = runner_utils.get_param_for_module(block_id, block_dict, 'extend_chained', True)

    if extend_chained and starting_list:
        try:
            chained.extend(starting_list)
        except (AttributeError, TypeError):
            log.error("Invalid argument type", exc_info=True)
            return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')
    try:
        ret = chained[index]
    except IndexError:
        log.error('List index out of range %d', index, exc_info=True)
        return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')
    except TypeError:
        log.error('Arguments should be of type list', exc_info=True)
        return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')
    
    status = bool(ret)
    if status:
        return runner_utils.prepare_positive_result_for_module(block_id, ret)
    return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_result')

def _get_key(block_id, block_dict, extra_args):
    """
    Given a dictionary, return an element by ``key``.

    block_id:
        Block id

    block_dict:
        key:           (Mandatory)
                        Key value to get
        starting_dict: (Optional)
                        Starting dictionary param
        extend_chained: (Default True)
                        By default, ``chained`` will have ``.update()`` called on it with
                        ``starting_dict`` as the only argument. Set ``extend_chained`` to False
                        to ignore ``starting_dict``.

    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "Output", 'status': True},
                  'caller': 'Audit'}

    The first return value (status) will be True if the key is found, and
    False othewise. The second argument will be the value found by the key or
    None if the key is not present in the dictionary.
    """
    chained = runner_utils.get_chained_param(extra_args)

    key = runner_utils.get_param_for_module(block_id, block_dict, 'key')
    starting_dict = runner_utils.get_param_for_module(block_id, block_dict, 'starting_dict')
    update_chained = runner_utils.get_param_for_module(block_id, block_dict, 'update_chained', True)

    if update_chained and starting_dict:
        try:
            chained.update(starting_dict)
        except (TypeError, ValueError):
            log.error("Arguments should be of type dict.", exc_info=True)
            return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')
    try:
        ret = chained[key]
    except KeyError:
        log.error("Key not found: %s", key, exc_info=True)
        return runner_utils.prepare_negative_result_for_module(block_id, 'key_not_found')
        return False, None
    except TypeError:
        log.error("Arguments should be of type dict.", exc_info=True)
        return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')
    status = bool(ret)

    if not status:
        return runner_utils.prepare_negative_result_for_module(block_id, 'unknown_error')
    return runner_utils.prepare_positive_result_for_module(block_id, ret)

def _join(block_id, block_dict, extra_args):
    """
    Given a list of strings, join them into a string, using ``sep`` as delimiter.

    block_id:
        Block id

    block_dict:
        words:          (Mandatory)
                        List of string
        sep:            (Optional)
                        Separator, Default: ''
        extend_chained: (Default True)
                        By default, ``chained`` will have ``.extend()`` called on it with
                        ``words`` as the only argument.

    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "Output", 'status': True},
                  'caller': 'Audit'}

    The first return value (status) will be True if the join was successful, and
    False othewise. The second argument will be the output of the ``join``
    command.

    ``extend_chained`` is set to True when ``chained`` should be extended with ``words``.
    If set to False, ``words`` is ignored.
    """
    chained = runner_utils.get_chained_param(extra_args)

    extend_chained = runner_utils.get_param_for_module(block_id, block_dict, 'extend_chained', True)
    sep = runner_utils.get_param_for_module(block_id, block_dict, 'sep', '')
    words = runner_utils.get_param_for_module(block_id, block_dict, 'words', None)

    if extend_chained and words:
        try:
            chained.extend(words)
        except (AttributeError, TypeError):
            log.error("Arguments should be of type list.", exc_info=True)
            return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')
    try:
        ret = sep.join(chained)
    except (TypeError, AttributeError):
        log.error("Invalid arguments type.", exc_info=True)
        return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')
    
    status = bool(ret)
    if not status:
        return runner_utils.prepare_negative_result_for_module(block_id, 'unknown_error')

    return runner_utils.prepare_positive_result_for_module(block_id, ret)

def _sort(block_id, block_dict, extra_args):
    """
    Given a target sequence, sort it and return the sorted result.

    block_id:
        Block id

    block_dict:
        seq:            (Optional)
                        Input sequence to be sorted
        lexico:         (Optional) (Default False)
                        Set to True if the sorting thould be in lexicographical order.
        desc:           (Optional) (Default False)
                        Set to True if the sorting should be in descending order.
        extend_chained: (Default True)
                        By default, ``chained`` will have ``.extend()`` or 
                        ``.update()`` or ``.format()``
                        called on it with ``seq`` as the only argument. 
                        Set ``extend_chained`` to False to ignore ``seq``.

    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "Output", 'status': True},
                  'caller': 'Audit'}

    The first return value (status) will be True if the sort is successful, and
    False othewise. The second argument will be the sorted sequence.
    """
    chained = runner_utils.get_chained_param(extra_args)

    extend_chained = runner_utils.get_param_for_module(block_id, block_dict, 'extend_chained', True)
    lexico = runner_utils.get_param_for_module(block_id, block_dict, 'lexico', False)
    desc = runner_utils.get_param_for_module(block_id, block_dict, 'desc', False)
    seq = runner_utils.get_param_for_module(block_id, block_dict, 'seq')

    if extend_chained and seq:
        try:
            if isinstance(chained, (dict, set)):
                chained.update(seq)
            elif isinstance(chained, list):
                chained.extend(seq)
            elif isinstance(chained, str):
                chained = seq.format(chained)
        except (AttributeError, TypeError, ValueError):
            log.error("Invalid arguments type.", exc_info=True)
            return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')
    ret = _sort_helper(chained, desc, lexico)
    status = bool(ret)

    if not status:
        return runner_utils.prepare_negative_result_for_module(block_id, 'unknown_error')
    return runner_utils.prepare_positive_result_for_module(block_id, ret)


def _sort_helper(seq,
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

def _split(block_id, block_dict, extra_args):
    """
    Given a ``phrase`` string, split it into a list of words by a ``sep`` delimiter.

    block_id:
        Block id

    block_dict:
        phrase:         (Mandatory)
                        Input Phrase(string) to be split.
        sep:            (Optional)
                        Separator to split by. It can either be a delimiter or a regex.
                        If it's None it will split by whitespace.
        regex:          (Optional) (Default False)
                        Set to True if ``sep`` should be treated as a regex instead of a delimiter.
        format_chained: (Default True)
                        By default, the ``phrase`` will have ``.format()`` called on it with
                        ``chained`` as the only argument. (So, use ``{0}`` in your phrase to
                        substitute the chained value.) If you want to avoid having to escape
                        curly braces, set ``format_chained=False``.

    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "Output", 'status': True},
                  'caller': 'Audit'}

    The first return value (status) will be True if the delimiter is found and
    the splitting is successful, and False othewise. The second argument will be
    the output of the ``split`` command.
    """
    chained = runner_utils.get_chained_param(extra_args)

    format_chained = runner_utils.get_param_for_module(block_id, block_dict, 'format_chained', True)
    phrase = runner_utils.get_param_for_module(block_id, block_dict, 'phrase')
    sep = runner_utils.get_param_for_module(block_id, block_dict, 'sep')
    regex = runner_utils.get_param_for_module(block_id, block_dict, 'regex', False)

    if format_chained and chained:
        try:
            phrase = phrase.format(chained)
        except AttributeError:
            log.error("Invalid attributes type.", exc_info=True)
            return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')
    ret = _split_helper(phrase, sep, regex)
    status = bool(ret) and len(ret) > 1

    if not status:
        return runner_utils.prepare_negative_result_for_module(block_id, 'unknown_error')
    return runner_utils.prepare_positive_result_for_module(block_id, ret)

def _split_helper(phrase,
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

def _dict_to_list(block_id, block_dict, extra_args):
    """
    Given a target dictionary, convert it to a list of (key, value) tuples.

    block_id:
        Block id

    block_dict:
        starting_dict:  (Optional)
                        Initial dictionary
        update_chained: (Default True)
                        By default, ``chained`` will have ``.update()`` called on it with
                        ``starting_dict`` as the only argument.
                        Set ``update_chained`` to False to ignore ``starting_dict``.

    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "Output", 'status': True},
                  'caller': 'Audit'}

    The first return value (status) will be True if the conversion is successful,
    and False othewise. The second argument will be the list of tuples.
    """
    chained = runner_utils.get_chained_param(extra_args)

    update_chained = runner_utils.get_param_for_module(block_id, block_dict, 'update_chained', True)
    starting_dict = runner_utils.get_param_for_module(block_id, block_dict, 'starting_dict')
    
    if update_chained and starting_dict:
        try:
            chained.update(starting_dict)
        except (AttributeError, ValueError, TypeError):
            log.error("Invalid arguments type.", exc_info=True)
            return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')
    ret = [(key, value) for key, value in chained.items()]
    status = bool(ret)

    if not status:
        return runner_utils.prepare_negative_result_for_module(block_id, 'unknown_error')
    return runner_utils.prepare_positive_result_for_module(block_id, ret)


def _dict_convert_none(block_id, block_dict, extra_args):
    """
    Given a target sequence, look for dictionary keys that have empty string values
     and replace them with None.

    block_id:
        Block id

    block_dict:
        starting_dict:  (Optional)
                        Initial dictionary
        extend_chained: (Default True)
                        By default, ``chained`` will have ``.extend()`` or  ``.update()``  called on it with
                        ``starting_seq`` as the only argument.
                        Set ``extend_chained`` to False to ignore ``starting_seq``.

    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "Output", 'status': True},
                  'caller': 'Audit'}

    The first return value (status) will be True if the replacing is successful, and
    False othewise. The second argument will be the updated sequence.
    """
    chained = runner_utils.get_chained_param(extra_args)

    extend_chained = runner_utils.get_param_for_module(block_id, block_dict, 'extend_chained', True)
    starting_seq = runner_utils.get_param_for_module(block_id, block_dict, 'starting_seq')
    
    if extend_chained and starting_seq:
        try:
            if isinstance(chained, (set, dict)):
                chained.update(starting_seq)
            elif isinstance(chained, list):
                chained.extend(starting_seq)
        except (AttributeError, TypeError, ValueError):
            log.error("Invalid type of arguments", exc_info=True)
            return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')
    if isinstance(chained, dict):
        ret = _dict_convert_none_helper(chained)
    elif isinstance(chained, (set, list, tuple)):
        ret = _seq_convert_none_helper(chained)
    else:
        log.error("Invalid arguments type - dict or sequence expected")
        return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_error')
    status = bool(ret)

    if not status:
        return runner_utils.prepare_negative_result_for_module(block_id, 'unknown_error')
    return runner_utils.prepare_positive_result_for_module(block_id, ret)


def _dict_convert_none_helper(dictionary):
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
            updated_dict[key] = _dict_convert_none_helper(value)
        elif isinstance(value, (list, set, tuple)):
            updated_dict[key] = _seq_convert_none_helper(value)
        else:
            updated_dict[key] = value

    return updated_dict


def _seq_convert_none_helper(seq):
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
            updated_seq.append(_dict_convert_none_helper(element))
        elif isinstance(element, (list, set, tuple)):
            updated_seq.append(_seq_convert_none_helper(element))
        else:
            updated_seq.append(element)

    return updated_seq

def _print_string(block_id, block_dict, extra_args):
    """
    Given a string, return it.

    block_id:
        Block id

    block_dict:
        starting_string:  (Optional)
                        Initial string
        format_chained: (Default True)
                        By default, ``starting_string`` will have ``.format()`` called on it
                        with ``chained`` as the only argument. (So, use ``{0}`` in your pattern to
                        substitute the chained value.) If you want to avoid having to escape curly braces,
                        set ``format_chained=False``.

    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "Output", 'status': True},
                  'caller': 'Audit'}

    The first return value (status) will be False only if an error will occur.
    """
    chained = runner_utils.get_chained_param(extra_args)

    format_chained = runner_utils.get_param_for_module(block_id, block_dict, 'format_chained', True)
    starting_string = runner_utils.get_param_for_module(block_id, block_dict, 'starting_string')

    if format_chained:
        try:
            starting_string = starting_string.format(chained)
        except AttributeError:
            log.error("Invalid type for starting_string - has to be string.", exc_info=True)
            return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')
    if not isinstance(starting_string, str):
        log.error('Invalid arguments - starting_string should be a string')
        return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')

    if not bool(starting_string):
        return runner_utils.prepare_negative_result_for_module(block_id, 'unknown_error')
    return runner_utils.prepare_positive_result_for_module(block_id, starting_string)

def _dict_remove_none(block_id, block_dict, extra_args):
    """
    Given a target sequence, look for dictionary keys that have values of None and remove them.

    block_id:
        Block id

    block_dict:
        starting_seq:  (Optional)
                        Initial sequence
        extend_chained: (Default True)
                        By default, ``chained`` will have ``.extend()`` or ``.update()`` called on it with
                        ``starting_seq`` as the only argument.
                        Set ``extend_chained`` to False to ignore ``starting_seq``.

    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "Output", 'status': True},
                  'caller': 'Audit'}

    The first return value (status) will be True if the sterilizing is successful,
    and False otherwise.
    The second argument will be the sterilized sequence.
    """
    chained = runner_utils.get_chained_param(extra_args)

    extend_chained = runner_utils.get_param_for_module(block_id, block_dict, 'extend_chained', True)
    starting_seq = runner_utils.get_param_for_module(block_id, block_dict, 'starting_seq')

    if extend_chained and starting_seq:
        try:
            if isinstance(chained, (set, dict)):
                chained.update(starting_seq)
            elif isinstance(chained, list):
                chained.extend(starting_seq)
        except (AttributeError, TypeError, ValueError):
            log.error("Invalid arguments type", exc_info=True)
            return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')
    if isinstance(chained, dict):
        ret = _sterilize_dict(chained)
    elif isinstance(chained, (list, set, tuple)):
        ret = _sterilize_seq(chained)
    else:
        log.error("Invalid arguments type - dict, list, set or tuple expected")
        return runner_utils.prepare_negative_result_for_module(block_id, 'invalid_format')
    
    status = bool(ret)
    if not status:
        return runner_utils.prepare_negative_result_for_module(block_id, 'unknown_error')
    return runner_utils.prepare_positive_result_for_module(block_id, ret)


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

def _nop(block_id, block_dict, extra_args):
    """
    This function just returns the chained value. It is a nop/no operation.

    This can be useful if you want to do a pipe_on_true to filter out
    False values -- you can pipe_on_true to process.nop, and stick a
    returner on the nop operation to just return the True values.
    """
    return runner_utils.get_chained_param(extra_args)

def _encode_base64(block_id, block_dict, extra_args):
    """
    Given a string, base64 encode it and return it.

    block_id:
        Block id

    block_dict:
        starting_string:(Optional)
                        Initial string
        format_chained: (Default True)
                        By default, ``starting_string`` will have ``.format()`` called on it
                        with ``chained`` as the only argument. (So, use ``{0}`` in your pattern to
                        substitute the chained value.) If you want to avoid having to escape curly braces,
                        set ``format_chained=False``.

    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "Output", 'status': True},
                  'caller': 'Audit'}

    The first return value (status) will be False only if an error will occur.
    """
    chained = runner_utils.get_chained_param(extra_args)

    format_chained = runner_utils.get_param_for_module(block_id, block_dict, 'format_chained', True)
    starting_string = runner_utils.get_param_for_module(block_id, block_dict, 'starting_string')

    status, ret = utils_encode_base64(starting_string, format_chained=format_chained,
                               chained=chained)
    if not status:
        return runner_utils.prepare_negative_result_for_module(block_id, 'unknown_error')
    return runner_utils.prepare_positive_result_for_module(block_id, ret)

def get_filtered_params_to_log(block_id, block_dict, extra_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "string/dict", 'status': True},
                  'extra_args': [{'check_id': 'ADOBE-01',
                                  'check_status': 'Success'}]
                  'caller': 'FDG'}
    """
    log.debug('get_filtered_params_to_log for id: {0}'.format(block_id))

    # fetch required param
    function_param = runner_utils.get_param_for_module(block_id, block_dict, 'function')

    return {'function': function_param}
