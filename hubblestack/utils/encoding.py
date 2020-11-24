#!/usr/bin/env python
# coding: utf-8

import logging
import base64
import salt.ext.six as six

log = logging.getLogger(__name__)


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
    if format_chained:
        try:
            starting_string = starting_string.format(chained)
        except AttributeError:
            log.error("Invalid type for starting_string - has to be string.", exc_info=True)
            return False, None
    if not isinstance(starting_string, str):
        log.error('Invalid arguments - starting_string should be a string')
        return False, None
    # compatbility with python2 & 3
    if six.PY3:
        ret = base64.b64encode(bytes(starting_string, 'utf-8'))
        # convert from bytes to str
        ret = ret.decode('ascii')
    else:
        ret = base64.b64encode(starting_string)

    return bool(ret), ret

def encode_something_to_bytes(x):
    """ take strings or bytes or whatever and convert to bytes """
    if isinstance(x, (bytes,bytearray)):
        return x
    return x.encode('utf-8')

def decode_something_to_string(x):
    """ take strings or bytes or whatever and convert to string """
    if isinstance(x, (bytes,bytearray)):
        return x.decode('utf-8')
    return x
