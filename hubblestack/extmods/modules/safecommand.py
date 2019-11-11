# -*- encoding: utf-8 -*-
"""
Safe Command
============

The idea behind this module is to allow an arbitrary command to be executed
safely, with the arguments to the specified binary (optionally) coming from
the fileserver.

For example, you might have some internal license auditing application for
which you need the ability to modify the command line arguments from
hubblestack_data. But what you don't want is the ability to execute arbitrary
commands from hubblestack_data. You also want to avoid command injection.

This module allows for this functionality.
"""

import logging

from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def run(command, args=None, override_file=None, timeout=30):
    """
    This function allows a specific command to be run, with the option to have
    command-line arguments for the command to be defined in hubblestack_data.

    The command is run with python_shell=False, which will prevent command
    injection.

    command
        The command to be run. Usually just the binary name, but can also
        include arguments/flags that need to be inserted to make the command
        safe, such as sandbox flags.

    args
        The rest of the args for the command. Can be a string or a list.

    override_file
        A fileserver location (``salt://this/is/a/path.txt``). The contents
        of the file at this location will be used *instead of* ``args``

    timeout
        Limit the cmd.run to ``timeout`` seconds. Default 30
    """
    # Convert a list of args to a string
    if isinstance(args, (list, tuple)):
        args = ' '.join(args)

    if not args:
        args = None

    # Check for an override file for args
    override_args = None
    if override_file:
        override = __salt__['cp.cache_file'](override_file)
        if override:
            try:
                with open(override, 'r') as args_file:
                    override_args = args_file.read().strip()
            except Exception as exc:
                log.exception('Error caching file %s', override_file)
                raise CommandExecutionError(exc)

    # Use override_args if we found any
    if override_args is not None:
        args = override_args

    # Run the command with the final args
    if not args:
        ret = __salt__['cmd.run'](command, python_shell=False, timeout=timeout)
    else:
        ret = __salt__['cmd.run']('{0} {1}'.format(command, args),
                                  python_shell=False, timeout=timeout)

    return ret
