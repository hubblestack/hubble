"""
Flexible Data Gathering: readfile
=================================

This fdg module allows for reading in the contents of files, with various
options for format and filtering.
"""


import json as _json
import logging
import os
import re

import yaml as _yaml

from hubblestack.utils.encoding import encode_base64

log = logging.getLogger(__name__)


def json(path, subkey=None, sep=None, chained=None, chained_status=None):
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

    chained
        Value passed in via chaining in fdg. Will be called with ``.format()``
        on the path and subkey if defined.

    chained_status
        The status returned by the chained function.
    """
    if chained is not None:
        path = path.format(chained)
        if subkey:
            subkey = subkey.format(chained)

    if not os.path.isfile(path):
        log.error('Path %s not found.', path)
        return False, None

    ret = None
    try:
        with open(path, 'r') as jfile:
            ret = _json.load(jfile)
    except Exception:
        log.error('Error reading file %s.', path, exc_info=True)

    if subkey:
        if sep is not None:
            subkey = subkey.split(sep)
        else:
            subkey = [subkey]
        try:
            # Traverse dictionary
            for key in subkey:
                if not isinstance(ret, dict):
                    # If it's not a dict, assume it's a list and that `key` is an int
                    key = int(key)
                ret = ret[key]
        except (KeyError, TypeError, ValueError, IndexError):
            log.error('Error traversing dict.', exc_info=True)
            return False, None

    return True, ret


def yaml(path, subkey=None, sep=None, chained=None, chained_status=None):
    """
    Pull data (optionally from a subkey) of a yaml object in a file at ``path``

    path
        Path of file to be read in

    subkey
        Optional. Key to pull out of yaml dict. If ``sep`` is defined, you can
        use it to separate subkeys and pull a value out of the depths of a
        dictionary. Note that we try to detect non-dict objects and assume if
        we find a non-dict object that it is a list, and that the subkey at
        that level is an integer.

    sep
        Separator in ``subkey``. If not defined, ``subkey`` will not be split.

    chained
        Value passed in via chaining in fdg. Will be called with ``.format()``
        on the path and subkey if defined.

    chained_status
        Status returned by the chained function.
    """
    if chained is not None:
        path = path.format(chained)
        if subkey:
            subkey = subkey.format(chained)

    if not os.path.isfile(path):
        log.error('Path %s not found.', path)
        return False, None

    ret = None
    try:
        with open(path, 'r') as yaml_file:
            ret = _yaml.safe_load(yaml_file)
    except Exception:
        log.error('Error reading file %s.', path, exc_info=True)

    if subkey:
        if sep is not None:
            subkey = subkey.split(sep)
        else:
            subkey = [subkey]
        try:
            # Traverse dictionary
            for key in subkey:
                if not isinstance(ret, dict):
                    # If it's not a dict, assume it's a list and that `key` is an int
                    key = int(key)
                ret = ret[key]
        except (TypeError, ValueError, KeyError, IndexError):
            log.error('Error traversing dict.', exc_info=True)
            return False, None

    return True, ret


def config(path,
           pattern=None,
           ignore_pattern=None,
           dictsep=None,
           valsep=None,
           subsep=None,
           chained=None,
           chained_status=None):
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

    chained
        Chained values will be called with ``.format()`` on the ``path``.

    chained_status
        Status returned by the chained function.


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
    if chained is not None:
        path = path.format(chained)

    if not os.path.isfile(path):
        log.error('Path %s not found.', path)
        return False, None

    if dictsep is None:
        ret = _lines_as_list(path, pattern, ignore_pattern)
    else:
        # Lines as key/value pairs in a dict
        ret = _lines_as_dict(path, pattern, ignore_pattern, dictsep, valsep, subsep)

    return ret is not None, ret


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


def readfile_string(path, encode_b64=False, chained=None, chained_status=None):
    """
    Open the file at ``path``, read its contents and return them as a string.

    path
        Path of file to be read in

    encode_64
        Set to `True` if the return string should be base64 encoded.
        Defaults to `False` which returns a regular string.

    format_chained

    chained
        Value passed in via chaining in fdg. Will be called with ``.format()``
        on the path if defined.

    chained_status
        Status returned by the chained function.
    """
    if chained is not None:
        path = path.format(chained)

    if not os.path.isfile(path):
        log.error('Path %s not found.', path)
        return False, None
    try:
        with open(path, 'r') as input_file:
            ret = input_file.read()
    except Exception:
        log.error('Error reading file %s', path, exc_info=True)
        return False, None
    status = bool(ret)
    if encode_b64:
        status, ret = encode_base64(ret, format_chained=False)

    return status, ret
