'''
Flexible Data Gathering: readfile
=================================

This fdg module allows for reading in the contents of files, with various
options for format and filtering.
'''
from __future__ import absolute_import
import json as _json
import logging
import os
import re
import yaml as _yaml

from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def json(path, subkey=None, sep=None, chained=None):
    '''
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
    '''
    if chained is not None:
        path = path.format(chained)
        if subkey:
            subkey = subkey.format(chained)

    if not os.path.isfile(path):
        log.error('Path {0} not found.'.format(path))
        return False, None

    ret = None
    try:
        with open(path, 'r') as f:
            ret = _json.load(f)
    except Exception as exc:
        log.error('Error reading file {0}: {1}'.format(path, exc))

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
        except Exception as exc:
            log.error('Error traversing dict: {0}'.format(exc))
            return False, None

    return True, ret


def yaml(path, subkey=None, sep=None, chained=None):
    '''
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
    '''
    if chained is not None:
        path = path.format(chained)
        if subkey:
            subkey = subkey.format(chained)

    if not os.path.isfile(path):
        log.error('Path {0} not found.'.format(path))
        return False, None

    ret = None
    try:
        with open(path, 'r') as f:
            ret = _yaml.safe_load(f)
    except Exception as exc:
        log.error('Error reading file {0}: {1}'.format(path, exc))

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
        except Exception as exc:
            log.error('Error traversing dict: {0}'.format(exc))
            return False, None

    return True, ret


def config(path,
           pattern=None,
           ignore_pattern=None,
           dictsep=None,
           valsep=None,
           subsep=None,
           chained=None):
    '''
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
    '''
    pass


