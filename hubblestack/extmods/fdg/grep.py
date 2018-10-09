# -*- encoding: utf-8 -*-
'''
Flexible Data Gathering: grep
=============================

This fdg module allows for grepping against files
'''
from __future__ import absolute_import
import logging
import os.path

from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def grep(path, pattern, grep_args, format_chained=True, chained=None):
    '''
    Given a target ``path``, call ``grep`` to search for for ``pattern`` in that
    file.

    By default, the ``pattern`` will have ``.format()`` called on it with
    ``chained`` as the only argument. (So, use ``{0}`` in your pattern to
    substitute the chained value.) If you want to avoid having to escape
    curly braces, set ``format_chained=False``.

    The first return value (status) will be True if the pattern is found, and
    False othewise. The second argument will be the output of the ``grep``
    command.

    ``grep_args`` can be used to pass in arguments to grep.
    '''
    if format_chained:
        pattern = pattern.format(chained)
    ret = _grep(path, pattern, *grep_args)
    status = bool(ret)
    return status, ret


def _grep(path,
          pattern,
          *args):
    '''
    Grep for a string in the specified file

    .. note::
        This function's return value is slated for refinement in future
        versions of Salt

    path
        Path to the file to be searched

        .. note::
            Globbing is supported (i.e. ``/var/log/foo/*.log``, but if globbing
            is being used then the path should be quoted to keep the shell from
            attempting to expand the glob expression.

    pattern
        Pattern to match. For example: ``test``, or ``a[0-5]``

    opts
        Additional command-line flags to pass to the grep command. For example:
        ``-v``, or ``-i -B2``

        .. note::
            The options should come after a double-dash (as shown in the
            examples below) to keep Salt's own argument parser from
            interpreting them.

    CLI Example:

    .. code-block:: bash

        salt '*' file.grep /etc/passwd nobody
        salt '*' file.grep /etc/sysconfig/network-scripts/ifcfg-eth0 ipaddr -- -i
        salt '*' file.grep /etc/sysconfig/network-scripts/ifcfg-eth0 ipaddr -- -i -B2
        salt '*' file.grep "/etc/sysconfig/network-scripts/*" ipaddr -- -i -l
    '''
    path = os.path.expanduser(path)

    if args:
        options = ' '.join(args)
    else:
        options = ''
    cmd = (
        r'''grep  {options} {pattern} {path}'''
        .format(
            options=options,
            pattern=pattern,
            path=path,
        )
    )

    try:
        ret = __salt__['cmd.run_all'](cmd, python_shell=False, ignore_retcode=True)
    except (IOError, OSError) as exc:
        raise CommandExecutionError(exc.strerror)

    return ret
