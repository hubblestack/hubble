# -*- coding: utf-8 -*-
'''
Functions used for CLI argument handling
'''

import shlex
import logging

from hubblestack.utils.exceptions import HubbleInvocationError
import hubblestack.utils.data
import hubblestack.utils.stringutils

log = logging.getLogger(__name__)

def clean_kwargs(**kwargs):
    '''
    Return a dict without any of the __pub* keys (or any other keys starting
    with a dunder) from the kwargs dict passed into the execution module
    functions. These keys are useful for tracking what was used to invoke
    the function call, but they may not be desirable to have if passing the
    kwargs forward wholesale.

    Usage example:

    .. code-block:: python

        kwargs = __utils__['args.clean_kwargs'](**kwargs)
    '''
    ret = {}
    for key, val in iter(kwargs.items()):
        if not key.startswith('__'):
            ret[key] = val
    return ret


def invalid_kwargs(invalid_kwargs, raise_exc=True):
    '''
    Raise a HubbleInvocationError if invalid_kwargs is non-empty
    '''
    if invalid_kwargs:
        if isinstance(invalid_kwargs, dict):
            new_invalid = [
                '{0}={1}'.format(x, y)
                for x, y in iter(invalid_kwargs.items())
            ]
            invalid_kwargs = new_invalid
    msg = (
        'The following keyword arguments are not valid: {0}'
        .format(', '.join(invalid_kwargs))
    )
    if raise_exc:
        raise HubbleInvocationError(msg)
    else:
        return msg

def shlex_split(s, **kwargs):
    '''
    Only split if variable is a string
    '''
    if isinstance(s, str):
        return hubblestack.utils.data.decode(
            shlex.split(hubblestack.utils.stringutils.to_str(s), **kwargs)
        )
    else:
        return s

