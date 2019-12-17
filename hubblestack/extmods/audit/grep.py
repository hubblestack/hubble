# -*- encoding: utf-8 -*-
"""
Audit module for using grep to verify settings in files.

Sample YAML data:

.. code-block:: yaml

    CIS-6.2.4:
      grep.grep:
        args:
          - /etc/group
        kwargs:
          pattern: '^+:'
          fail_on_match: True
        description: Ensure no legacy "+" entries exist in /etc/group

Required args/kwargs:

    path
        The absolute path of the file to match against
    pattern
        The pattern to use with the ``grep`` command.

Optional kwargs:

    grep_args
        A list of args to pass to the ``grep`` command
    fail_on_match
        Defaults to False. If set to True, then if a match is found it will
        count as a failure.
    success_on_file_missing
        Defaults to False. If set to True, then if a file is missing this check
        will be marked as a success.
    match_output
        String to check for in the output of the grep command. If not provided,
        any grep output will be considered a match.
    match_output_regex
        True/False. Whether to use regex when matching output. Defaults to
        False.
    match_output_multiline
        True/False. Whether to use multiline flag for regex matching with
        match_output_regex set to True. Defaults to True.
"""


import logging
import os
import re

from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def grep(path,
         pattern,
         grep_args=None,
         fail_on_match=False,
         success_on_file_missing=False,
         match_output=None,
         match_output_regex=False,
         match_output_multiline=True):
    """
    Use grep to match against the contents of a file.

    :param path:
        See module-level documentation
    :param pattern:
        See module-level documentation
    :param grep_args:
        See module-level documentation
    :param fail_on_match:
        See module-level documentation
    :param success_on_file_missing:
        See module-level documentation
    :param match_output:
        See module-level documentation
    :param match_output_regex:
        See module-level documentation
    :param match_output_multiline:
        See module-level documentation
    :return:
        Returns a tuple (success, {'grep_output': output}) where ``success``
        is True or False based on the success of the check, and ``output`` is
        the output of the ``grep`` command, for documentation purposes.
    """
    if not os.path.isfile(path):
        if success_on_file_missing:
            return True, {'reason': 'File missing'}
        return False, {'reason': 'File missing'}

    if not grep_args:
        grep_args = []

    output = _grep(path, pattern, *grep_args)

    if not output:
        # No output found
        if fail_on_match:
            return True, {'grep_output': output}
        return False, {'grep_output': output}

    # We default to ``success = True`` because there was grep output. Now we'll
    # check against the various match_output settings to see if we need to
    # reverse that decision
    success = True
    if match_output:
        if match_output_regex:
            if match_output_multiline:
                if not re.search(match_output, output, re.MULTILINE):
                    success = False
            else:
                if not re.search(match_output, output):
                    success = False
        else:
            if match_output not in output:
                success = False

    # Reverse our success if ``fail_on_match = True``
    if fail_on_match:
        success = not success

    return success, {'grep_output': output}


def _grep(path,
          pattern,
          *args):
    """
    Grep for a string in the specified file

    :param path:
        Path to the file to be searched
    :param pattern:
        Pattern to match. For example: ``test``, or ``a[0-5]``
    :param args:
        Additional command-line flags to pass to the grep command. For example:
        ``-v``, or ``-i -B2``
    :return:
    """
    path = os.path.expanduser(path)

    if args:
        options = ' '.join(args)
    else:
        options = ''
    cmd = r'grep {options} {pattern} {path}'.format(options=options,
                                                    pattern=pattern,
                                                    path=path)

    try:
        ret = __salt__['cmd.run'](cmd, python_shell=False, ignore_retcode=True)
    except (IOError, OSError) as exc:
        raise CommandExecutionError(exc.strerror)

    return ret
