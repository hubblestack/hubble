# -*- coding: utf-8 -*-
'''
Functions used for CLI argument handling
'''

import shlex
import logging
import inspect

from hubblestack.exceptions import HubbleInvocationError
import hubblestack.utils.data
import hubblestack.utils.stringutils

log = logging.getLogger(__name__)

from collections import namedtuple  # pylint: disable=wrong-import-position,wrong-import-order

_ArgSpec = namedtuple('ArgSpec', 'args varargs keywords defaults')


def _getargspec(func):
    '''
    Python 3 wrapper for inspect.getargsspec

    inspect.getargsspec is deprecated and will be removed in Python 3.6.
    '''
    args, varargs, varkw, defaults, kwonlyargs, _, ann = \
        inspect.getfullargspec(func)  # pylint: disable=no-member
    if kwonlyargs or ann:
        raise ValueError('Function has keyword-only arguments or annotations'
                         ', use getfullargspec() API which can support them')
    return _ArgSpec(args, varargs, varkw, defaults)


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


def split_input(val, mapper=None):
    '''
    Take an input value and split it into a list, returning the resulting list
    '''
    if mapper is None:
        mapper = lambda x: x
    if isinstance(val, list):
        return list(map(mapper, val))
    try:
        return list(map(mapper, [x.strip() for x in val.split(',')]))
    except AttributeError:
        return list(map(mapper, [x.strip() for x in str(val).split(',')]))


def get_function_argspec(func, is_class_method=None):
    '''
    A small wrapper around getargspec that also supports callable classes
    :param is_class_method: Pass True if you are sure that the function being passed
                            is a class method. The reason for this is that on Python 3
                            ``inspect.ismethod`` only returns ``True`` for bound methods,
                            while on Python 2, it returns ``True`` for bound and unbound
                            methods. So, on Python 3, in case of a class method, you'd
                            need the class to which the function belongs to be instantiated
                            and this is not always wanted.
    '''
    if not callable(func):
        raise TypeError('{0} is not a callable'.format(func))

    if is_class_method is True:
        aspec = _getargspec(func)
        del aspec.args[0]  # self
    elif inspect.isfunction(func):
        aspec = _getargspec(func)  # pylint: disable=redefined-variable-type
    elif inspect.ismethod(func):
        aspec = _getargspec(func)
        del aspec.args[0]  # self
    elif isinstance(func, object):
        aspec = _getargspec(func.__call__)
        del aspec.args[0]  # self
    else:
        raise TypeError(
            'Cannot inspect argument list for \'{0}\''.format(func)
        )
    return aspec


def test_mode(**kwargs):
    """
    Examines the kwargs passed and returns True if any kwarg which matching
    "Test" in any variation on capitalization (i.e. "TEST", "Test", "TeSt",
    etc) contains a True value (as determined by hubblestack.utils.data.is_true).
    """
    # Once is_true is moved, remove this import and fix the ref below

    for arg, value in kwargs.items():
        try:
            if arg.lower() == "test" and hubblestack.utils.data.is_true(value):
                return True
        except AttributeError:
            continue
    return False
