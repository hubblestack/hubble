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
import yaml

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
