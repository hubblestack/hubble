# -*- encoding: utf-8 -*-
"""
Flexible Data Gathering: grep
=============================

This fdg module allows for grepping against files and strings
"""

import logging
import os.path

from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def file(path, pattern, grep_args=None, format_chained=True, chained=None, chained_status=None):
    """
    Given a target ``path``, call ``grep`` to search for for ``pattern`` in that
    file.

    By default, the ``pattern`` and ``path`` will have ``.format()`` called on them with
    ``chained`` as the only argument. (So, use ``{0}`` in your pattern to
    substitute the chained value.) If you want to avoid having to escape curly braces,
    set ``format_chained=False``.

    chained_status
        Status returned by the chained method.

    The first return value (status) will be True if the pattern is found, and
    False othewise. The second argument will be the output of the ``grep``
    command.

    ``grep_args`` can be used to pass in arguments to grep.
    """
    if format_chained:
        pattern = pattern.format(chained)
        path = path.format(chained)
    if grep_args is None:
        grep_args = []
    ret = _grep(pattern, path=path, args=grep_args)
    status = bool(ret)

    return status, ret


def stdin(pattern, starting_string=None, grep_args=None,
          format_chained=True, chained=None, chained_status=None):
    """
    Given a target string, call ``grep`` to search for for ``pattern`` in that
    string.

    By default, the ``starting_string`` will have ``.format()`` called on it with
    ``chained`` as the only argument. (So, use ``{0}`` in your pattern to
    substitute the chained value.) If you want to avoid having to escape
    curly braces, set ``format_chained=False``.

    chained_status
        Status returned by the chained method.

    .. note::
        If no ``starting_string`` is provided, the ``chained``value  will be used.

    The first return value (status) will be True if the pattern is found, and
    False othewise. The second argument will be the output of the ``grep``
    command.

    ``grep_args`` can be used to pass in arguments to grep.
    """
    if format_chained:
        if starting_string:
            chained = starting_string.format(chained)

    if grep_args is None:
        grep_args = []
    ret = _grep(pattern, string=chained, args=grep_args)
    status = bool(ret)

    return status, ret


def _grep(pattern, path=None, string=None, args=None):
    """
    Grep for a string in the specified file or string

    .. note::
        This function's return value is slated for refinement in future
        versions of Salt

    pattern
        Pattern to match. For example: ``test``, or ``a[0-5]``

    path
        Path to the file to be searched

        .. note::
            Globbing is supported (i.e. ``/var/log/foo/*.log``, but if globbing
            is being used then the path should be quoted to keep the shell from
            attempting to expand the glob expression.

    string
        String to search

    args
        Optionally pass a list of flags to pass to the grep command. For example:
        ``-v`` or ``-i`` or ``-B2``
.. note::
            The options should come after a double-dash (as shown in the
            examples below) to keep Salt's own argument parser from
            interpreting them.

    CLI Example:

    .. code-block:: bash

        salt '*' file.grep /etc/passwd nobody
        salt '*' file.grep /etc/sysconfig/network-scripts/ifcfg-eth0 ipaddr '[-i, -B2]'
        salt '*' file.grep /etc/sysconfig/network-scripts/ifcfg-eth0 ipaddr '[-i, -B2]'
        salt '*' file.grep "/etc/sysconfig/network-scripts/*" ipaddr '[-i, -B2]'
    """
    if path:
        path = os.path.expanduser(path)

    options = []
    if args and not isinstance(args, (list, tuple)):
        args = [args]
    for arg in args:
        options += arg.split()
    cmd = ['grep'] + options + [pattern]
    if path:
        cmd += [path]

    try:
        ret = __salt__['cmd.run_stdout'](cmd, python_shell=False, ignore_retcode=True, stdin=string)
    except (IOError, OSError) as exc:
        raise CommandExecutionError(exc.strerror)

    return ret
