# -*- encoding: utf-8 -*-
'''
Flexible Data Gathering: split
=============================

This fdg module allows splitting a string into a list
'''
from __future__ import absolute_import
import re


def split(phrase, sep=None, regex=False, format_chained=True, chained=None):
    '''
    Given a ``phrase`` string, split it into a list of words by a ``sep`` delimiter.

    By default, the ``phrase`` will have ``.format()`` called on it with
    ``chained`` as the only argument. (So, use ``{0}`` in your phrase to
    substitute the chained value.) If you want to avoid having to escape
    curly braces, set ``format_chained=False``.

    The first return value (status) will be True if the delimiter is found and
    the splitting is successful, and False othewise. The second argument will be
    the output of the ``split`` command.

    ``regex`` will be set to True if ``sep`` is a regex instead of a pattern.

    '''
    if format_chained:
        phrase = phrase.format(chained)
    ret = _split(phrase, sep, regex)
    status = bool(ret) and len(ret) > 1
    return status, ret


def _split(phrase,
           sep,
           regex):
    '''
    Run the split command on the phrase using ``sep`` as a delimiter or regex.

    phrase
        The string to be split.

    sep
        Separator to split by. It can either be a delimiter or a regex.
        If it's None it will split by whitespace.

    regex
        Set to True if ``sep`` should be treated as a regex instead of a delimiter.
    '''
    ret = []
    if regex:
        ret = re.split(sep, phrase)
    else:
        ret = phrase.split(sep)
    return ret
