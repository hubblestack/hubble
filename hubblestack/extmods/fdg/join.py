# -*- encoding: utf-8 -*-
'''
Flexible Data Gathering: join
=============================

This fdg module allows joining a list of strings into a string
'''
from __future__ import absolute_import

from salt.exceptions import ArgumentValueError


def join(words, sep='', append_chained=True, chained=None):
    '''
    Given a list of strings ``words``, join them into a string, using ``sep`` as delimiter.

    By default, the ``words`` will have ``.extend()`` called on it with
    ``chained`` as the only argument.

    The first return value (status) will be True if the join was successful, and
    False othewise. The second argument will be the output of the ``join``
    command.

    ``append_chained`` is set to True when ``words`` should be extended with ``chained``.
    If set to False, chained is ignored.
    '''
    if append_chained:
        if chained:
            words.extend(chained)
    try:
        ret = sep.join(words)
    except (TypeError, AttributeError) as exc:
        raise ArgumentValueError(str(exc))
    status = bool(ret)
    return status, ret
