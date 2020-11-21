# -*- encoding: utf-8 -*-
"""
readfile module allows for reading in the contents of files, with various
options for format and filtering.
- json
- yaml
- config
- string

Note: Now each module just returns its output (As Data gathering)
      For Audit checks, comparison logic is now moved to comparators. 
      See below sections for more understanding

Usable in Modules
-----------------
- Audit
- FDG

Common Schema
-------------
- check_unique_id
    Its a unique string within a yaml file.
    It is present on top of a yaml block

- description 
    Description of the check

- tag 
    (Applicable only for Audit)
    Check tag value

- sub_check (Optional, default: false) 
    (Applicable only for Audit)
    If true, its individual result will not be counted in compliance
    It might be referred in some boolean expression

- failure_reason (Optional) 
    (Applicable only for Audit)
    By default, module will generate failure reason string at runtime
    If this is passed, this will override module's actual failure reason

- invert_result (Optional, default: false) 
    (Applicable only for Audit)
    This is used to flip the boolean output from a check

- implementations
    (Applicable only for Audit)
    Its an array of implementations, usually for multiple operating systems.
    You can specify multiple implementations here for respective operating system.
    Either one or none will be executed.

- grains (under filter)
    (Applicable only for Audit)
    Any grains with and/or/not supported. This is used to filter whether 
    this check can run on the current OS or not.
    To run this check on all OS, put a '*'

    Example:
    G@docker_details:installed:True and G@docker_details:running:True and not G@osfinger:*Flatcar* and not G@osfinger:*CoreOS*

- hubble_version (Optional)
    (Applicable only for Audit)
    It acts as a second level filter where you can specify for which Hubble version,
    this check is compatible with. You can specify a boolean expression as well

    Example:
    '>3.0 AND <5.0'

- module
    The name of Hubble module.

- return_no_exec (Optional, Default: false)
    (Applicable only for Audit)
    It takes a boolean (true/false) value.
    If its true, the implementation will not be executed. And true is returned
    
    This can be useful in cases where you don't have any implementation for some OS,
    and you want a result from the block. Else, your meta-check(bexpr) will be failed.

- items
    (Applicable only for Audit)
    An array of multiple module implementations. At least one block is necessary.
    Each item in array will result into a boolean value.
    If multiple module implementations exists, final result will be evaluated as 
    boolean AND (default, see parameter: check_eval_logic)

- check_eval_logic (Optional, default: and)
    (Applicable only for Audit)
    If there are multiple module implementations in "items" (above parameter), this parameter
    helps in evaluating their result. Default value is "and"
    It accepts only values: and/or

- args
    Arguments specific to a module.

- comparator
    For the purpose of comparing output of module with expected values.
    Parameters depends upon the comparator used.
    For detailed documentation on comparators, 
    read comparator's implementations at (/hubblestack/extmods/comparators/)

FDG Schema
----------
FDG schema is kept simple. Only following keywords allowed:
- Unique id
    Unique string id
- description (Optional)
    Some description
- module
    Name of the module
- args
    Module arguments
- comparator (Only in case of Audit-FDG connector)

FDG Chaining
------------
In normal execution, this module expects a filepath. 
In case of chaining, it expects a string from the chained parameter

Module Arguments
----------------
- path
    Path of file to read
- format
    Format of the file (json, yaml, config, string)
- Format specific parameters
    - For file format: json and yaml
        path - Path of file
        subkey - (Optional) Key to pull out
        sep - (Optional) Separator to split subkey
        chaining (If used in chaining)
            Chained values will be called with ``.format()`` on the ``path``.

    - For file format: config
        path - Path of file
        pattern - (Optional) if specified, Only lines with this pattern will be collected
                regex supported
        ignore_pattern - (Optional) Lines with this pattern will be ignored. 
                        This overrides ``pattern``
        dictsep - (Optional) Because this is a config-like file, we assume that each line
                has a key and a value. This is the separator for that key and value.
                If no ``dictsep`` is provided, we will take the whole line and just
                return a list of strings instead of a dict with keys and values.
                
                Note also that if a file, like the sample data above, has duplicate
                keys, there will be one key in the resulting dict, with a list
                of values underneath that key.
        valsep - (Optional). A value could be a list, with a defined separator. If this
                is defined, values will be split on this character or string.
        subsep - Optional. There can be key-value pairs within a value. 
                If this argument is defined, we will split the value (or
                each member of the value list if ``valsep`` is defined) and turn the
                result into a key-value pair in a dictionary. If this is defined in
                conjunction with ``valsep``, the result will be a dictionary, not
                a list of single-key dictionaries.

        chaining (If used in chaining)
                Chained values will be called with ``.format()`` on the ``path``.

    - For file format: string
        path - Path of file
        encode_64 - (Optional) Set to `True` if the return string should be base64 encoded.
            Defaults to `False` which returns a regular string.

        chaining (If used in chaining)
            Chained values will be called with ``.format()`` on the ``path``.

Module Output
-------------
Value of the item searched, or the file content

Output: (True, "item2")
Note: Module returns a tuple
    First value being the status of module
    Second value is the actual output from module

Compatible Comparators
----------------------
Since output is pretty dynamic. Following comparators can be used:
- string
- boolean
- list
- dict
- number

For detailed documentation on comparators,
read comparator's implementations at (/hubblestack/extmods/comparators/)


Audit Example
-------------
check_unique_id:
  description: 'readfile check'
  tag: 'ADOBE-01'
  sub_check: false (Optional, default: false)
  failure_reason: 'a sample failure reason' (Optional)
  invert_result: false (Optional, default: false)
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      # return_no_exec: true (Optional, default: false)
      check_eval_logic: and (Optional, default: and)
      module: readfile
      items:
        - args:
            "path": '/file/path',
            "format": "json",
            "subkey": 'id'
          comparator:
            type: "string"
            match: "string_to_match"

FDG Example:
------------
main:
  description: 'readfile check'
  module: readfile
  args:
    path: '/file/path',
    "format": "json",
    "subkey": 'id'
"""

import os
import logging
import json as _json
import yaml as _yaml
import re

from hubblestack.utils.encoding import encode_base64
import hubblestack.module_runner.runner_utils as runner_utils
from hubblestack.exceptions import HubbleCheckValidationError

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
        Example: {'chaining_args': {'result': '/some/path', 'status': True},
                  'caller': 'Audit'}

    Raises:
        HubbleCheckValidationError: For any validation error
    """
    log.debug('Module: readfile Start validating params for check-id: {0}'.format(block_id))

    filepath = runner_utils.get_param_for_module(block_id, block_dict, 'path')
    file_format = runner_utils.get_param_for_module(block_id, block_dict, 'format')

    error = {}
    if not filepath:
        error['path'] = 'No filepath provided'
    if not file_format:
        error['format'] = 'No file format provided'

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
        Example: {'chaining_args': {'result': '/some/path', 'status': True},
                  'caller': 'Audit'}

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing readfile module for id: {0}'.format(block_id))

    file_format = runner_utils.get_param_for_module(block_id, block_dict, 'format')
    if file_format in ['json', 'yaml']:
        return _handle_file(file_format, block_id, block_dict, extra_args)
    elif file_format == 'config':
        return _handle_config_file(block_id, block_dict, extra_args)
    elif file_format == 'string':
        return _handle_string_file(block_id, block_dict, extra_args)
    else:
        return runner_utils.prepare_negative_result_for_module(block_id, 'Unknown file format')


def _handle_file(file_format, block_id, block_dict, extra_args=None):
    path = runner_utils.get_param_for_module(block_id, block_dict, 'path')
    chained_param = runner_utils.get_chained_param(extra_args)
    subkey = runner_utils.get_param_for_module(block_id, block_dict, 'subkey')
    sep = runner_utils.get_param_for_module(block_id, block_dict, 'sep')

    return _handle_file_helper(file_format, block_id, path, subkey, sep, chained_param)


def _handle_file_helper(file_format, block_id, path, subkey=None, sep=None, chained_param=None):
    """
    Pull data (optionally from a subkey) of a json object in a file at ``path``

    path
        Path of file to be read in

    subkey
        Optional. Key to pull out of json dict. If ``sep`` is defined, you can
        use it to separate subkeys and pull a value out of the depths of a
        dictionary. Note that we try to detect non-dict objects and assume if
        we find a non-dict object that it is a list, and that the subkey at
        that level is an integer.

    sep
        Separator in ``subkey``. If not defined, ``subkey`` will not be split.

    chained_param
        Value passed in via chaining in fdg. Will be called with ``.format()``
        on the path and subkey if defined.
    """
    if chained_param:
        path = path.format(chained_param)
        if subkey:
            subkey = subkey.format(chained_param)

    if not os.path.isfile(path):
        log.error('Path %s not found.', path)
        return runner_utils.prepare_negative_result_for_module(block_id, 'file_not_found')

    ret = None
    try:
        with open(path, 'r') as file_handle:
            if file_format == 'json':
                ret = _json.load(file_handle)
            elif file_format == 'yaml':
                ret = _yaml.safe_load(file_handle)
            else:
                return runner_utils.prepare_negative_result_for_module(block_id, 'unknown_format')
    except Exception:
        log.error('Error reading file %s.', path, exc_info=True)
        return runner_utils.prepare_negative_result_for_module(block_id, 'exception while reading file')

    if subkey:
        subkey = [subkey] if not sep else subkey.split(sep)
        try:
            # Traverse dictionary
            for key in subkey:
                if not isinstance(ret, dict):
                    # If it's not a dict, assume it's a list and that `key` is an int
                    key = int(key)
                if key in ret:
                    ret = ret[key]
                elif isinstance(key, int):
                    ret = ret[key]
                else:
                    log.error("key '%s' not found in dictionary '%s'", key, ret)
                    return runner_utils.prepare_negative_result_for_module(block_id, 'KeyError')
        except (KeyError, TypeError, ValueError, IndexError):
            log.error('Error traversing dict.', exc_info=True)
            return runner_utils.prepare_negative_result_for_module(block_id, 'unknown_error')

    return runner_utils.prepare_positive_result_for_module(block_id, ret)


def _handle_config_file(block_id, block_dict, extra_args=None):
    path = runner_utils.get_param_for_module(block_id, block_dict, 'path')
    chained_param = runner_utils.get_chained_param(extra_args)
    pattern = runner_utils.get_param_for_module(block_id, block_dict, 'pattern')
    ignore_pattern = runner_utils.get_param_for_module(block_id, block_dict, 'ignore_pattern')
    dictsep = runner_utils.get_param_for_module(block_id, block_dict, 'dictsep')
    valsep = runner_utils.get_param_for_module(block_id, block_dict, 'valsep')
    subsep = runner_utils.get_param_for_module(block_id, block_dict, 'subsep')

    return _handle_config_helper(
        block_id, path, pattern, ignore_pattern, dictsep, valsep, subsep, chained_param)


def _handle_config_helper(block_id,
                          path,
                          pattern=None,
                          ignore_pattern=None,
                          dictsep=None,
                          valsep=None,
                          subsep=None,
                          chained_param=None):
    """
    This is a fairly specialized function designed to pull data from a file
    with formatting similar to this::

        APP_ATTRIBUTES=cluster_role:control;zone:3;provider:aws
        APP_ATTRIBUTES=cluster_role:worker;zone:1;provider:aws
        APP_ATTRIBUTES=cluster_role:master;zone:0;provider:aws

    The arguments decide how the data is parsed and are documented below.

    path
        Required argument. The file from which data will be extracted.

    pattern
        Optional. Only lines with this pattern will be collected. Regex is
        supported. If ``pattern`` is not provided, the whole file will be
        collected.

    ignore_pattern
        Optional. Lines with this pattern will be ignored. This overrides
        ``pattern``.

    dictsep
        Optional. Because this is a config-like file, we assume that each line
        has a key and a value. This is the separator for that key and value.
        If no ``dictsep`` is provided, we will take the whole line and just
        return a list of strings instead of a dict with keys and values.

        Note also that if a file, like the sample data above, has duplicate
        keys, there will be one key in the resulting dict, with a list
        of values underneath that key.

    valsep
        Optional. A value could be a list, with a defined separator. If this
        is defined, values will be split on this character or string.

    subsep
        Optional. As in the example above, there can be key-value pairs within
        a value. If this argument is defined, we will split the value (or
        each member of the value list if ``valsep`` is defined) and turn the
        result into a key-value pair in a dictionary. If this is defined in
        conjunction with ``valsep``, the result will be a dictionary, not
        a list of single-key dictionaries.

    chained_param
        Chained values will be called with ``.format()`` on the ``path``.

    Example:

    Assuming we have a file ``/tmp/data`` with the lines shown in the sample
    data above, we could write an fdg file like this:

    .. code-block:: yaml

        main:
          module: readfile.config
          kwargs:
            path: /tmp/data
            pattern: '^APP_ATTRIBUTES'
            dictsep: '='
            valsep: ';'
            subsep: ':'

    We would have this data (shown as json)

    .. code-block:: json

        {"APP_ATTRIBUTES":
            [
                {"cluster_role": "control",
                 "zone": "3",
                 "provider": "aws"},
                {"cluster_role": "worker",
                 "zone": "1",
                 "provider": "aws"},
                {"cluster_role": "master",
                 "zone": "0",
                 "provider": "aws"}
            ]
        }
    """
    if chained_param is not None:
        path = path.format(chained_param)

    if not os.path.isfile(path):
        log.error('Path %s not found.', path)
        return runner_utils.prepare_negative_result_for_module(block_id, 'file_not_found')

    if dictsep is None:
        ret = _lines_as_list(path, pattern, ignore_pattern)
    else:
        # Lines as key/value pairs in a dict
        ret = _lines_as_dict(path, pattern, ignore_pattern, dictsep, valsep, subsep)

    if ret is not None:
        return runner_utils.prepare_positive_result_for_module(block_id, ret)

    return runner_utils.prepare_negative_result_for_module(block_id, ret)


def _lines_as_list(path, pattern, ignore_pattern):
    """
    Helper function for config. Process lines as list of strings.
    """
    try:
        # All lines as list of strings
        if not pattern and not ignore_pattern:
            with open(path, 'r') as input_file:
                ret = input_file.readlines()
                ret = [s.strip() for s in ret]
                return ret
        # Some lines as a list of strings
        ret = []
        with open(path, 'r') as input_file:
            for line in input_file:
                line = line.strip()
                if not _check_pattern(line, pattern, ignore_pattern):
                    continue
                ret.append(line)
    except Exception:
        log.error('Error while processing readfile.config for file %s.', path, exc_info=True)
        return None

    return ret


def _lines_as_dict(path, pattern, ignore_pattern, dictsep, valsep, subsep):
    """
    Helper function for congig. Process lines as dict.
    """
    ret = {}
    found_keys = set()
    processed_keys = set()

    try:
        with open(path, 'r') as input_file:
            for line in input_file:
                line = line.strip()
                if not _check_pattern(line, pattern, ignore_pattern):
                    continue
                key, val = _process_line(line, dictsep, valsep, subsep)
                if key in found_keys and key not in processed_keys:
                    # Duplicate keys, make it a list of values underneath
                    # and add to list of values
                    ret[key] = [ret[key]]
                    ret[key].append(val)
                    processed_keys.add(key)
                elif key in found_keys and key in processed_keys:
                    # Duplicate keys, add to list of values
                    ret[key].append(val)
                else:
                    # First found, add to dict as normal
                    ret[key] = val
                    found_keys.add(key)
    except Exception:
        log.error('Error while processing readfile.config for file %s.', path, exc_info=True)
        return None

    return ret


def _check_pattern(line, pattern, ignore_pattern):
    """
    Check a given line against both a pattern and an ignore_pattern and return
    True or False based on whether that line should be used.
    """
    keep = False

    if pattern is None:
        keep = True
    elif re.match(pattern, line):
        keep = True

    if ignore_pattern is not None and re.match(ignore_pattern, line):
        keep = False

    return keep


def _process_line(line, dictsep, valsep, subsep):
    """
    Process a given line of data using the dictsep, valsep, and subsep
    provided. For documentation, please see the docstring for ``config()``
    """
    if dictsep is None:
        return line, None

    try:
        key, val = line.split(dictsep, 1)
    except (AttributeError, ValueError, TypeError):
        return line, None

    if valsep is not None:
        # List of values
        val = val.split(valsep)

        # List of key-value pairs to form into a dict
        if subsep is not None:
            new_val = {}
            for subval in val:
                try:
                    val_key, val_val = subval.split(subsep, 1)
                except (AttributeError, ValueError, TypeError):
                    val_key, val_val = subval, None
                new_val[val_key] = val_val
            val = new_val
    elif subsep is not None:
        # Single key-value pair to form into a dict
        try:
            val_key, val_val = val.split(subsep, 1)
        except (AttributeError, ValueError, TypeError):
            val_key, val_val = val, None
        val = {val_key: val_val}

    return key, val


def _handle_string_file(block_id, block_dict, extra_args=None):
    path = runner_utils.get_param_for_module(block_id, block_dict, 'path')
    chained_param = runner_utils.get_chained_param(extra_args)
    encode_b64 = runner_utils.get_param_for_module(block_id, block_dict, 'encode_b64')

    return _readfile_string(
        block_id, path, encode_b64, chained_param)


def _readfile_string(block_id, path, encode_b64=False, chained_param=None):
    """
    Open the file at ``path``, read its contents and return them as a string.

    path
        Path of file to be read in

    encode_64
        Set to `True` if the return string should be base64 encoded.
        Defaults to `False` which returns a regular string.

    chained_param
        Value passed in via chaining in fdg. Will be called with ``.format()``
        on the path if defined.
    """
    if chained_param is not None:
        path = path.format(chained_param)

    if not os.path.isfile(path):
        log.error('Path %s not found.', path)
        return runner_utils.prepare_negative_result_for_module(block_id, 'file_not_found')
    with open(path, 'r') as input_file:
        ret = input_file.read()
    status = bool(ret)
    if encode_b64:
        status, ret = encode_base64(ret, format_chained=False)

    return status, ret


def get_filtered_params_to_log(block_id, block_dict, extra_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': '/some/path', 'status': True},
                  'caller': 'Audit'}
    """
    log.debug('get_filtered_params_to_log for id: {0}'.format(block_id))

    # fetch required param
    filepath = runner_utils.get_param_for_module(block_id, block_dict, 'path')
    return {'path': filepath}
