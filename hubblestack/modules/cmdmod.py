# -*- coding: utf-8 -*-
'''
A module for shelling out.

Keep in mind that this module is insecure, in that it can give whomever has
access to the master root execution access to all salt minions.
'''

# Import python libs
import functools
import glob
import logging
import os
import shutil
import subprocess
import sys
import time
import traceback
import fnmatch
import base64
import re
import tempfile

import hubblestack.utils.args
import hubblestack.utils.data
import hubblestack.utils.files
import hubblestack.utils.path
import hubblestack.utils.platform
import hubblestack.utils.stringutils
import hubblestack.utils.timed_subprocess
import hubblestack.grains.extra
import hubblestack.utils.user
import hubblestack.grains.extra
from hubblestack.exceptions import CommandExecutionError, TimedProcTimeoutError, \
    HubbleInvocationError
from hubblestack.log import LOG_LEVELS

# Only available on POSIX systems, nonfatal on windows
try:
    import pwd
    import grp
except ImportError:
    pass

if hubblestack.utils.platform.is_windows():
    from hubblestack.utils.win_runas import runas as win_runas
    from hubblestack.utils.win_functions import escape_argument as _cmd_quote
    HAS_WIN_RUNAS = True
else:
    from shlex import quote as _cmd_quote
    HAS_WIN_RUNAS = False

# Define the module's virtual name
__virtualname__ = 'cmd'

# Set up logging
log = logging.getLogger(__name__)

DEFAULT_SHELL = hubblestack.grains.extra.shell()['shell']


# Overwriting the cmd python module makes debugging modules with pdb a bit
# harder so lets do it this way instead.
def __virtual__():
    return __virtualname__

def run_stdout(cmd,
               cwd=None,
               stdin=None,
               runas=None,
               group=None,
               shell=DEFAULT_SHELL,
               python_shell=None,
               env=None,
               clean_env=False,
               rstrip=True,
               umask=None,
               output_encoding=None,
               output_loglevel='debug',
               log_callback=None,
               hide_output=False,
               timeout=None,
               reset_system_locale=True,
               ignore_retcode=False,
               saltenv='base',
               password=None,
               prepend_path=None,
               success_retcodes=None,
               **kwargs):
    '''
    Execute a command, and only return the standard out

    :param str cmd: The command to run. ex: ``ls -lart /home``

    :param str cwd: The directory from which to execute the command. Defaults
        to the home directory of the user specified by ``runas`` (or the user
        under which Salt is running if ``runas`` is not specified).

    :param str stdin: A string of standard input can be specified for the
        command to be run using the ``stdin`` parameter. This can be useful in
        cases where sensitive information must be read from standard input.

    :param str runas: Specify an alternate user to run the command. The default
        behavior is to run as the user under which Salt is running. If running
        on a Windows minion you must also use the ``password`` argument, and
        the target user account must be in the Administrators group.

        .. warning::

            For versions 2018.3.3 and above on macosx while using runas,
            to pass special characters to the command you need to escape
            the characters on the shell.

            Example:

            .. code-block:: bash

                cmd.run_stdout 'echo '\\''h=\\"baz\\"'\\\''' runas=macuser

    :param str password: Windows only. Required when specifying ``runas``. This
        parameter will be ignored on non-Windows platforms.

        .. versionadded:: 2016.3.0

    :param str group: Group to run command as. Not currently supported
      on Windows.

    :param str shell: Specify an alternate shell. Defaults to the system's
        default shell.

    :param bool python_shell: If False, let python handle the positional
        arguments. Set to True to use shell features, such as pipes or
        redirection.

    :param dict env: Environment variables to be set prior to execution.

        .. note::
            When passing environment variables on the CLI, they should be
            passed as the string representation of a dictionary.

            .. code-block:: bash

                salt myminion cmd.run_stdout 'some command' env='{"FOO": "bar"}'

    :param bool clean_env: Attempt to clean out all other shell environment
        variables and set only those provided in the 'env' argument to this
        function.

    :param str prepend_path: $PATH segment to prepend (trailing ':' not necessary)
        to $PATH

        .. versionadded:: 2018.3.0

    :param bool rstrip: Strip all whitespace off the end of output before it is
        returned.

    :param str umask: The umask (in octal) to use when running the command.

    :param str output_encoding: Control the encoding used to decode the
        command's output.

        .. note::
            This should not need to be used in most cases. By default, Salt
            will try to use the encoding detected from the system locale, and
            will fall back to UTF-8 if this fails. This should only need to be
            used in cases where the output of the command is encoded in
            something other than the system locale or UTF-8.

            To see the encoding Salt has detected from the system locale, check
            the `locale` line in the output of :py:func:`test.versions_report
            <hubblestack.modules.test.versions_report>`.

        .. versionadded:: 2018.3.0

    :param str output_loglevel: Control the loglevel at which the output from
        the command is logged to the minion log.

        .. note::
            The command being run will still be logged at the ``debug``
            loglevel regardless, unless ``quiet`` is used for this value.

    :param bool ignore_retcode: If the exit code of the command is nonzero,
        this is treated as an error condition, and the output from the command
        will be logged to the minion log. However, there are some cases where
        programs use the return code for signaling and a nonzero exit code
        doesn't necessarily mean failure. Pass this argument as ``True`` to
        skip logging the output if the command has a nonzero exit code.

    :param bool hide_output: If ``True``, suppress stdout and stderr in the
        return data.

        .. note::
            This is separate from ``output_loglevel``, which only handles how
            Salt logs to the minion log.

        .. versionadded:: 2018.3.0

    :param int timeout: A timeout in seconds for the executed process to
        return.

    :param list success_retcodes: This parameter will be allow a list of
        non-zero return codes that should be considered a success.  If the
        return code returned from the run matches any in the provided list,
        the return code will be overridden with zero.

      .. versionadded:: 2019.2.0

    :param bool stdin_raw_newlines: False
        If ``True``, Salt will not automatically convert the characters ``\\n``
        present in the ``stdin`` value to newlines.

      .. versionadded:: 2019.2.0

    CLI Example:

    .. code-block:: bash

        salt '*' cmd.run_stdout "ls -l | awk '/foo/{print \\$2}'"

    A string of standard input can be specified for the command to be run using
    the ``stdin`` parameter. This can be useful in cases where sensitive
    information must be read from standard input.

    .. code-block:: bash

        salt '*' cmd.run_stdout "grep f" stdin='one\\ntwo\\nthree\\nfour\\nfive\\n'
    '''
    python_shell = _python_shell_default(python_shell,
                                         kwargs.get('__pub_jid', ''))
    ret = _run(cmd,
               runas=runas,
               group=group,
               cwd=cwd,
               stdin=stdin,
               shell=shell,
               python_shell=python_shell,
               env=env,
               clean_env=clean_env,
               prepend_path=prepend_path,
               rstrip=rstrip,
               umask=umask,
               output_encoding=output_encoding,
               output_loglevel=output_loglevel,
               log_callback=log_callback,
               timeout=timeout,
               reset_system_locale=reset_system_locale,
               ignore_retcode=ignore_retcode,
               saltenv=saltenv,
               password=password,
               success_retcodes=success_retcodes,
               **kwargs)

    return ret['stdout'] if not hide_output else ''

def _python_shell_default(python_shell, __pub_jid):
    '''
    Set python_shell default based on remote execution and __opts__['cmd_safe']
    '''
    try:
        # Default to python_shell=True when run directly from remote execution
        # system. Cross-module calls won't have a jid.
        if __pub_jid and python_shell is None:
            return True
        elif __opts__.get('cmd_safe', True) is False and python_shell is None:
            # Override-switch for python_shell
            return True
    except NameError:
        pass
    return python_shell

def _is_valid_shell(shell):
    '''
    Attempts to search for valid shells on a system and
    see if a given shell is in the list
    '''
    if hubblestack.utils.platform.is_windows():
        return True  # Don't even try this for Windows
    shells = '/etc/shells'
    available_shells = []
    if os.path.exists(shells):
        try:
            with hubblestack.utils.files.fopen(shells, 'r') as shell_fp:
                lines = [hubblestack.utils.stringutils.to_unicode(x)
                         for x in shell_fp.read().splitlines()]
            for line in lines:
                if line.startswith('#'):
                    continue
                else:
                    available_shells.append(line)
        except OSError:
            return True
    else:
        # No known method of determining available shells
        return None
    if shell in available_shells:
        return True
    else:
        return False

def _check_loglevel(level='info'):
    '''
    Retrieve the level code for use in logging.Logger.log().
    '''
    try:
        level = level.lower()
        if level == 'quiet':
            return None
        else:
            return LOG_LEVELS[level]
    except (AttributeError, KeyError):
        log.error(
            'Invalid output_loglevel \'%s\'. Valid levels are: %s. Falling '
            'back to \'info\'.',
            level, ', '.join(sorted(LOG_LEVELS, reverse=True))
        )
        return LOG_LEVELS['info']

def _check_cb(cb_):
    '''
    If the callback is None or is not callable, return a lambda that returns
    the value passed.
    '''
    if cb_ is not None:
        if hasattr(cb_, '__call__'):
            return cb_
        else:
            log.error('log_callback is not callable, ignoring')
    return lambda x: x

def _check_avail(cmd):
    '''
    Check to see if the given command can be run
    '''
    if isinstance(cmd, list):
        cmd = ' '.join([str(x) if not isinstance(x, str) else x
                        for x in cmd])
    bret = True
    wret = False
    if __salt__['config.get']('cmd_blacklist_glob'):
        blist = __salt__['config.get']('cmd_blacklist_glob', [])
        for comp in blist:
            if fnmatch.fnmatch(cmd, comp):
                # BAD! you are blacklisted
                bret = False
    if __salt__['config.get']('cmd_whitelist_glob', []):
        blist = __salt__['config.get']('cmd_whitelist_glob', [])
        for comp in blist:
            if fnmatch.fnmatch(cmd, comp):
                # GOOD! You are whitelisted
                wret = True
                break
    else:
        # If no whitelist set then alls good!
        wret = True
    return bret and wret

def _parse_env(env):
    if not env:
        env = {}
    if isinstance(env, list):
        env = hubblestack.utils.data.repack_dictlist(env)
    if not isinstance(env, dict):
        env = {}
    return env

def _run(cmd,
         cwd=None,
         stdin=None,
         stdout=subprocess.PIPE,
         stderr=subprocess.PIPE,
         output_encoding=None,
         output_loglevel='debug',
         log_callback=None,
         runas=None,
         group=None,
         shell=DEFAULT_SHELL,
         python_shell=False,
         env=None,
         clean_env=False,
         prepend_path=None,
         rstrip=True,
         umask=None,
         timeout=None,
         with_communicate=True,
         reset_system_locale=True,
         ignore_retcode=False,
         saltenv='base',
         pillarenv=None,
         pillar_override=None,
         password=None,
         bg=False,
         encoded_cmd=False,
         success_retcodes=None,
         **kwargs):
    '''
    Do the DRY thing and only call subprocess.Popen() once
    '''
    if 'pillar' in kwargs and not pillar_override:
        pillar_override = kwargs['pillar']
    if output_loglevel != 'quiet' and _is_valid_shell(shell) is False:
        log.warning(
            'Attempt to run a shell command with what may be an invalid shell! '
            'Check to ensure that the shell <%s> is valid for this user.',
            shell
        )

    output_loglevel = _check_loglevel(output_loglevel)
    log_callback = _check_cb(log_callback)
    use_sudo = False

    if runas is None and '__context__' in globals():
        runas = __context__.get('runas')

    if password is None and '__context__' in globals():
        password = __context__.get('runas_password')

    # Set the default working directory to the home directory of the user
    # salt-minion is running as. Defaults to home directory of user under which
    # the minion is running.
    if not cwd:
        cwd = os.path.expanduser('~{0}'.format('' if not runas else runas))

        # make sure we can access the cwd
        # when run from sudo or another environment where the euid is
        # changed ~ will expand to the home of the original uid and
        # the euid might not have access to it. See issue #1844
        if not os.access(cwd, os.R_OK):
            cwd = '/'
            if hubblestack.utils.platform.is_windows():
                cwd = os.path.abspath(os.sep)
    else:
        # Handle edge cases where numeric/other input is entered, and would be
        # yaml-ified into non-string types
        cwd = str(cwd)

    if bg:
        ignore_retcode = True

    if not hubblestack.utils.platform.is_windows():
        if not os.path.isfile(shell) or not os.access(shell, os.X_OK):
            msg = 'The shell {0} is not available'.format(shell)
            raise CommandExecutionError(msg)

    if shell.lower().strip() == 'powershell':
        # Strip whitespace
        if isinstance(cmd, str):
            cmd = cmd.strip()

        # If we were called by script(), then fakeout the Windows
        # shell to run a Powershell script.
        # Else just run a Powershell command.
        stack = traceback.extract_stack(limit=2)

        # extract_stack() returns a list of tuples.
        # The last item in the list [-1] is the current method.
        # The third item[2] in each tuple is the name of that method.
        if stack[-2][2] == 'script':
            cmd = 'Powershell -NonInteractive -NoProfile -ExecutionPolicy Bypass -File ' + cmd
        elif encoded_cmd:
            cmd = 'Powershell -NonInteractive -EncodedCommand {0}'.format(cmd)
        else:
            cmd = 'Powershell -NonInteractive -NoProfile "{0}"'.format(cmd.replace('"', '\\"'))

    ret = {}

    # If the pub jid is here then this is a remote ex or salt call command and needs to be
    # checked if blacklisted
    if '__pub_jid' in kwargs:
        if not _check_avail(cmd):
            raise CommandExecutionError(
                'The shell command "{0}" is not permitted'.format(cmd)
            )

    env = _parse_env(env)

    for bad_env_key in (x for x, y in iter(env.items()) if y is None):
        log.error('Environment variable \'%s\' passed without a value. '
                  'Setting value to an empty string', bad_env_key)
        env[bad_env_key] = ''

    def _get_stripped(cmd):
        # Return stripped command string copies to improve logging.
        if isinstance(cmd, list):
            return [x.strip() if isinstance(x, str) else x for x in cmd]
        elif isinstance(cmd, str):
            return cmd.strip()
        else:
            return cmd

    if output_loglevel is not None:
        # Always log the shell commands at INFO unless quiet logging is
        # requested. The command output is what will be controlled by the
        # 'loglevel' parameter.
        msg = (
            'Executing command {0}{1}{0} {2}{3}in directory \'{4}\'{5}'.format(
                '\'' if not isinstance(cmd, list) else '',
                _get_stripped(cmd),
                'as user \'{0}\' '.format(runas) if runas else '',
                'in group \'{0}\' '.format(group) if group else '',
                cwd,
                '. Executing command in the background, no output will be '
                'logged.' if bg else ''
            )
        )
        log.info(log_callback(msg))

    if runas and hubblestack.utils.platform.is_windows():
        if not HAS_WIN_RUNAS:
            msg = 'missing salt/utils/win_runas.py'
            raise CommandExecutionError(msg)

        if isinstance(cmd, (list, tuple)):
            cmd = ' '.join(cmd)

        return win_runas(cmd, runas, password, cwd)

    if runas and hubblestack.utils.platform.is_darwin():
        # We need to insert the user simulation into the command itself and not
        # just run it from the environment on macOS as that method doesn't work
        # properly when run as root for certain commands.
        if isinstance(cmd, (list, tuple)):
            cmd = ' '.join(map(_cmd_quote, cmd))

        # Ensure directory is correct before running command
        cmd = 'cd -- {dir} && {{ {cmd}\n }}'.format(dir=_cmd_quote(cwd), cmd=cmd)

        # Ensure environment is correct for a newly logged-in user by running
        # the command under bash as a login shell
        cmd = '/bin/bash -l -c {cmd}'.format(cmd=_cmd_quote(cmd))

        # Ensure the login is simulated correctly (note: su runs sh, not bash,
        # which causes the environment to be initialised incorrectly, which is
        # fixed by the previous line of code)
        cmd = 'su -l {0} -c {1}'.format(_cmd_quote(runas), _cmd_quote(cmd))

        # Set runas to None, because if you try to run `su -l` after changing
        # user, su will prompt for the password of the user and cause salt to
        # hang.
        runas = None

    if runas:
        # Save the original command before munging it
        try:
            pwd.getpwnam(runas)
        except KeyError:
            raise CommandExecutionError(
                'User \'{0}\' is not available'.format(runas)
            )

    if group:
        if hubblestack.utils.platform.is_windows():
            msg = 'group is not currently available on Windows'
            raise HubbleInvocationError(msg)
        if not hubblestack.utils.path.which_bin(['sudo']):
            msg = 'group argument requires sudo but not found'
            raise CommandExecutionError(msg)
        try:
            grp.getgrnam(group)
        except KeyError:
            raise CommandExecutionError(
                'Group \'{0}\' is not available'.format(runas)
            )
        else:
            use_sudo = True

    if runas or group:
        try:
            # Getting the environment for the runas user
            # Use markers to thwart any stdout noise
            # There must be a better way to do this.
            import uuid
            marker = '<<<' + str(uuid.uuid4()) + '>>>'
            marker_b = marker.encode(__salt_system_encoding__)
            py_code = (
                'import sys, os, itertools; '
                'sys.stdout.write(\"' + marker + '\"); '
                'sys.stdout.write(\"\\0\".join(itertools.chain(*os.environ.items()))); '
                'sys.stdout.write(\"' + marker + '\");'
            )

            if use_sudo:
                env_cmd = ['sudo']
                # runas is optional if use_sudo is set.
                if runas:
                    env_cmd.extend(['-u', runas])
                if group:
                    env_cmd.extend(['-g', group])
                if shell != DEFAULT_SHELL:
                    env_cmd.extend(['-s', '--', shell, '-c'])
                else:
                    env_cmd.extend(['-i', '--'])
                env_cmd.extend([sys.executable])
            elif __grains__['os'] in ['FreeBSD']:
                env_cmd = ('su', '-', runas, '-c',
                           "{0} -c {1}".format(shell, sys.executable))
            else:
                env_cmd = ('su', '-s', shell, '-', runas, '-c', sys.executable)
            msg = 'env command: {0}'.format(env_cmd)
            log.debug(log_callback(msg))

            env_bytes, env_encoded_err = subprocess.Popen(
                env_cmd,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE
            ).communicate(hubblestack.utils.stringutils.to_bytes(py_code))
            marker_count = env_bytes.count(marker_b)
            if marker_count == 0:
                # Possibly PAM prevented the login
                log.error(
                    'Environment could not be retrieved for user \'%s\': '
                    'stderr=%r stdout=%r',
                    runas, env_encoded_err, env_bytes
                )
                # Ensure that we get an empty env_runas dict below since we
                # were not able to get the environment.
                env_bytes = b''
            elif marker_count != 2:
                raise CommandExecutionError(
                    'Environment could not be retrieved for user \'{0}\'',
                    info={'stderr': repr(env_encoded_err),
                          'stdout': repr(env_bytes)}
                )
            else:
                # Strip the marker
                env_bytes = env_bytes.split(marker_b)[1]

            env_runas = dict(list(zip(*[iter(env_bytes.split(b'\0'))]*2)))

            env_runas = dict(
                (hubblestack.utils.stringutils.to_str(k),
                 hubblestack.utils.stringutils.to_str(v))
                for k, v in iter(env_runas.items())
            )
            env_runas.update(env)

            # Fix platforms like Solaris that don't set a USER env var in the
            # user's default environment as obtained above.
            if env_runas.get('USER') != runas:
                env_runas['USER'] = runas

            # Fix some corner cases where shelling out to get the user's
            # environment returns the wrong home directory.
            runas_home = os.path.expanduser('~{0}'.format(runas))
            if env_runas.get('HOME') != runas_home:
                env_runas['HOME'] = runas_home

            env = env_runas
        except ValueError as exc:
            log.exception('Error raised retrieving environment for user %s', runas)
            raise CommandExecutionError(
                'Environment could not be retrieved for user \'{0}\': {1}'.format(
                    runas, exc
                )
            )

    if reset_system_locale is True:
        if not hubblestack.utils.platform.is_windows():
            # Default to C!
            # Salt only knows how to parse English words
            # Don't override if the user has passed LC_ALL
            env.setdefault('LC_CTYPE', 'C')
            env.setdefault('LC_NUMERIC', 'C')
            env.setdefault('LC_TIME', 'C')
            env.setdefault('LC_COLLATE', 'C')
            env.setdefault('LC_MONETARY', 'C')
            env.setdefault('LC_MESSAGES', 'C')
            env.setdefault('LC_PAPER', 'C')
            env.setdefault('LC_NAME', 'C')
            env.setdefault('LC_ADDRESS', 'C')
            env.setdefault('LC_TELEPHONE', 'C')
            env.setdefault('LC_MEASUREMENT', 'C')
            env.setdefault('LC_IDENTIFICATION', 'C')
            env.setdefault('LANGUAGE', 'C')
        else:
            # On Windows set the codepage to US English.
            if python_shell:
                cmd = 'chcp 437 > nul & ' + cmd

    if clean_env:
        run_env = env
    else:
        if hubblestack.utils.platform.is_windows():
            import nt
            run_env = nt.environ.copy()
        else:
            run_env = os.environ.copy()
        run_env.update(env)

    if prepend_path:
        run_env['PATH'] = ':'.join((prepend_path, run_env['PATH']))

    if python_shell is None:
        python_shell = False

    new_kwargs = {'cwd': cwd,
                  'shell': python_shell,
                  'env': run_env,
                  'stdin': str(stdin) if stdin is not None else stdin,
                  'stdout': stdout,
                  'stderr': stderr,
                  'with_communicate': with_communicate,
                  'timeout': timeout,
                  'bg': bg,
                  }

    if 'stdin_raw_newlines' in kwargs:
        new_kwargs['stdin_raw_newlines'] = kwargs['stdin_raw_newlines']

    if umask is not None:
        _umask = str(umask).lstrip('0')

        if _umask == '':
            msg = 'Zero umask is not allowed.'
            raise CommandExecutionError(msg)

        try:
            _umask = int(_umask, 8)
        except ValueError:
            raise CommandExecutionError("Invalid umask: '{0}'".format(umask))
    else:
        _umask = None

    if runas or group or umask:
        new_kwargs['preexec_fn'] = functools.partial(
                hubblestack.utils.user.chugid_and_umask,
                runas,
                _umask,
                group)

    if not hubblestack.utils.platform.is_windows():
        # close_fds is not supported on Windows platforms if you redirect
        # stdin/stdout/stderr
        if new_kwargs['shell'] is True:
            new_kwargs['executable'] = shell
        new_kwargs['close_fds'] = True

    if not os.path.isabs(cwd) or not os.path.isdir(cwd):
        raise CommandExecutionError(
            'Specified cwd \'{0}\' either not absolute or does not exist'
            .format(cwd)
        )

    if python_shell is not True \
            and not hubblestack.utils.platform.is_windows() \
            and not isinstance(cmd, list):
        cmd = hubblestack.utils.args.shlex_split(cmd)

    if success_retcodes is None:
        success_retcodes = [0]
    else:
        try:
            success_retcodes = [int(i) for i in
                                hubblestack.utils.args.split_input(
                                    success_retcodes
                                )]
        except ValueError:
            raise HubbleInvocationError(
                'success_retcodes must be a list of integers'
            )

    # This is where the magic happens
    try:
        proc = hubblestack.utils.timed_subprocess.TimedProc(cmd, **new_kwargs)
    except (OSError, IOError) as exc:
        msg = (
            'Unable to run command \'{0}\' with the context \'{1}\', '
            'reason: '.format(
                cmd if output_loglevel is not None else 'REDACTED',
                new_kwargs
            )
        )
        try:
            if exc.filename is None:
                msg += 'command not found'
            else:
                msg += '{0}: {1}'.format(exc, exc.filename)
        except AttributeError:
            # Both IOError and OSError have the filename attribute, so this
            # is a precaution in case the exception classes in the previous
            # try/except are changed.
            msg += 'unknown'
        raise CommandExecutionError(msg)

    try:
        proc.run()
    except TimedProcTimeoutError as exc:
        ret['stdout'] = str(exc)
        ret['stderr'] = ''
        ret['retcode'] = None
        ret['pid'] = proc.process.pid
        # ok return code for timeouts?
        ret['retcode'] = 1
        return ret

    if output_loglevel != 'quiet' and output_encoding is not None:
        log.debug('Decoding output from command %s using %s encoding',
                    cmd, output_encoding)

    try:
        out = hubblestack.utils.stringutils.to_unicode(
            proc.stdout,
            encoding=output_encoding)
    except TypeError:
        # stdout is None
        out = ''
    except UnicodeDecodeError:
        out = hubblestack.utils.stringutils.to_unicode(
            proc.stdout,
            encoding=output_encoding,
            errors='replace')
        if output_loglevel != 'quiet':
            log.error(
                'Failed to decode stdout from command %s, non-decodable '
                'characters have been replaced', cmd
            )

    try:
        err = hubblestack.utils.stringutils.to_unicode(
            proc.stderr,
            encoding=output_encoding)
    except TypeError:
        # stderr is None
        err = ''
    except UnicodeDecodeError:
        err = hubblestack.utils.stringutils.to_unicode(
            proc.stderr,
            encoding=output_encoding,
            errors='replace')
        if output_loglevel != 'quiet':
            log.error(
                'Failed to decode stderr from command %s, non-decodable '
                'characters have been replaced', cmd
            )

    if rstrip:
        if out is not None:
            out = out.rstrip()
        if err is not None:
            err = err.rstrip()
    ret['pid'] = proc.process.pid
    ret['retcode'] = proc.process.returncode
    if ret['retcode'] in success_retcodes:
        ret['retcode'] = 0
    ret['stdout'] = out
    ret['stderr'] = err
    
    try:
        if ignore_retcode:
            __context__['retcode'] = 0
        else:
            __context__['retcode'] = ret['retcode']
    except NameError:
        # Ignore the context error during grain generation
        pass

    # Log the output
    if output_loglevel is not None:
        if not ignore_retcode and ret['retcode'] != 0:
            if output_loglevel < LOG_LEVELS['error']:
                output_loglevel = LOG_LEVELS['error']
            msg = (
                'Command \'{0}\' failed with return code: {1}'.format(
                    cmd,
                    ret['retcode']
                )
            )
            log.error(log_callback(msg))
        if ret['stdout']:
            log.log(output_loglevel, 'stdout: {0}'.format(log_callback(ret['stdout'])))
        if ret['stderr']:
            log.log(output_loglevel, 'stderr: {0}'.format(log_callback(ret['stderr'])))
        if ret['retcode']:
            log.log(output_loglevel, 'retcode: {0}'.format(ret['retcode']))

    return ret

def _run_quiet(cmd,
               cwd=None,
               stdin=None,
               output_encoding=None,
               runas=None,
               shell=DEFAULT_SHELL,
               python_shell=False,
               env=None,
               umask=None,
               timeout=None,
               reset_system_locale=True,
               saltenv='base',
               pillarenv=None,
               pillar_override=None,
               success_retcodes=None):
    '''
    Helper for running commands quietly for minion startup
    '''
    return _run(cmd,
                runas=runas,
                cwd=cwd,
                stdin=stdin,
                stderr=subprocess.STDOUT,
                output_encoding=output_encoding,
                output_loglevel='quiet',
                log_callback=None,
                shell=shell,
                python_shell=python_shell,
                env=env,
                umask=umask,
                timeout=timeout,
                reset_system_locale=reset_system_locale,
                saltenv=saltenv,
                pillarenv=pillarenv,
                pillar_override=pillar_override,
                success_retcodes=success_retcodes)['stdout']


def _run_all_quiet(cmd,
                   cwd=None,
                   stdin=None,
                   runas=None,
                   shell=DEFAULT_SHELL,
                   python_shell=False,
                   env=None,
                   umask=None,
                   timeout=None,
                   reset_system_locale=True,
                   saltenv='base',
                   pillarenv=None,
                   pillar_override=None,
                   output_encoding=None,
                   success_retcodes=None):

    '''
    Helper for running commands quietly for minion startup.
    Returns a dict of return data.

    output_loglevel argument is ignored. This is here for when we alias
    cmd.run_all directly to _run_all_quiet in certain chicken-and-egg
    situations where modules need to work both before and after
    the __salt__ dictionary is populated (cf dracr.py)
    '''
    return _run(cmd,
                runas=runas,
                cwd=cwd,
                stdin=stdin,
                shell=shell,
                python_shell=python_shell,
                env=env,
                output_encoding=output_encoding,
                output_loglevel='quiet',
                log_callback=None,
                umask=umask,
                timeout=timeout,
                reset_system_locale=reset_system_locale,
                saltenv=saltenv,
                pillarenv=pillarenv,
                pillar_override=pillar_override,
                success_retcodes=success_retcodes)

def run_all(cmd,
            cwd=None,
            stdin=None,
            runas=None,
            group=None,
            shell=DEFAULT_SHELL,
            python_shell=None,
            env=None,
            clean_env=False,
            rstrip=True,
            umask=None,
            output_encoding=None,
            output_loglevel='debug',
            log_callback=None,
            hide_output=False,
            timeout=None,
            reset_system_locale=True,
            ignore_retcode=False,
            saltenv='base',
            redirect_stderr=False,
            password=None,
            encoded_cmd=False,
            prepend_path=None,
            success_retcodes=None,
            **kwargs):
    '''
    Execute the passed command and return a dict of return data

    :param str cmd: The command to run. ex: ``ls -lart /home``

    :param str cwd: The directory from which to execute the command. Defaults
        to the home directory of the user specified by ``runas`` (or the user
        under which Salt is running if ``runas`` is not specified).

    :param str stdin: A string of standard input can be specified for the
        command to be run using the ``stdin`` parameter. This can be useful in
        cases where sensitive information must be read from standard input.

    :param str runas: Specify an alternate user to run the command. The default
        behavior is to run as the user under which Salt is running. If running
        on a Windows minion you must also use the ``password`` argument, and
        the target user account must be in the Administrators group.

        .. warning::

            For versions 2018.3.3 and above on macosx while using runas,
            to pass special characters to the command you need to escape
            the characters on the shell.

            Example:

            .. code-block:: bash

                cmd.run_all 'echo '\\''h=\\"baz\\"'\\\''' runas=macuser

    :param str password: Windows only. Required when specifying ``runas``. This
        parameter will be ignored on non-Windows platforms.

        .. versionadded:: 2016.3.0

    :param str group: Group to run command as. Not currently supported
      on Windows.

    :param str shell: Specify an alternate shell. Defaults to the system's
        default shell.

    :param bool python_shell: If False, let python handle the positional
        arguments. Set to True to use shell features, such as pipes or
        redirection.

    :param dict env: Environment variables to be set prior to execution.

        .. note::
            When passing environment variables on the CLI, they should be
            passed as the string representation of a dictionary.

            .. code-block:: bash

                salt myminion cmd.run_all 'some command' env='{"FOO": "bar"}'

    :param bool clean_env: Attempt to clean out all other shell environment
        variables and set only those provided in the 'env' argument to this
        function.

    :param str prepend_path: $PATH segment to prepend (trailing ':' not
        necessary) to $PATH

        .. versionadded:: 2018.3.0

    :param bool rstrip: Strip all whitespace off the end of output before it is
        returned.

    :param str umask: The umask (in octal) to use when running the command.

    :param str output_encoding: Control the encoding used to decode the
        command's output.

        .. note::
            This should not need to be used in most cases. By default, Salt
            will try to use the encoding detected from the system locale, and
            will fall back to UTF-8 if this fails. This should only need to be
            used in cases where the output of the command is encoded in
            something other than the system locale or UTF-8.

            To see the encoding Salt has detected from the system locale, check
            the `locale` line in the output of :py:func:`test.versions_report
            <hubblestack.modules.test.versions_report>`.

        .. versionadded:: 2018.3.0

    :param str output_loglevel: Control the loglevel at which the output from
        the command is logged to the minion log.

        .. note::
            The command being run will still be logged at the ``debug``
            loglevel regardless, unless ``quiet`` is used for this value.

    :param bool ignore_retcode: If the exit code of the command is nonzero,
        this is treated as an error condition, and the output from the command
        will be logged to the minion log. However, there are some cases where
        programs use the return code for signaling and a nonzero exit code
        doesn't necessarily mean failure. Pass this argument as ``True`` to
        skip logging the output if the command has a nonzero exit code.

    :param bool hide_output: If ``True``, suppress stdout and stderr in the
        return data.

        .. note::
            This is separate from ``output_loglevel``, which only handles how
            Salt logs to the minion log.

        .. versionadded:: 2018.3.0

    :param int timeout: A timeout in seconds for the executed process to
        return.

    :param bool encoded_cmd: Specify if the supplied command is encoded.
       Only applies to shell 'powershell'.

       .. versionadded:: 2018.3.0

    :param bool redirect_stderr: If set to ``True``, then stderr will be
        redirected to stdout. This is helpful for cases where obtaining both
        the retcode and output is desired, but it is not desired to have the
        output separated into both stdout and stderr.

        .. versionadded:: 2015.8.2

    :param str password: Windows only. Required when specifying ``runas``. This
        parameter will be ignored on non-Windows platforms.

          .. versionadded:: 2016.3.0

    :param bool bg: If ``True``, run command in background and do not await or
        deliver its results

        .. versionadded:: 2016.3.6

    :param list success_retcodes: This parameter will be allow a list of
        non-zero return codes that should be considered a success.  If the
        return code returned from the run matches any in the provided list,
        the return code will be overridden with zero.

      .. versionadded:: 2019.2.0

    :param bool stdin_raw_newlines: False
        If ``True``, Salt will not automatically convert the characters ``\\n``
        present in the ``stdin`` value to newlines.

      .. versionadded:: 2019.2.0

    CLI Example:

    .. code-block:: bash

        salt '*' cmd.run_all "ls -l | awk '/foo/{print \\$2}'"

    A string of standard input can be specified for the command to be run using
    the ``stdin`` parameter. This can be useful in cases where sensitive
    information must be read from standard input.

    .. code-block:: bash

        salt '*' cmd.run_all "grep f" stdin='one\\ntwo\\nthree\\nfour\\nfive\\n'
    '''
    python_shell = _python_shell_default(python_shell,
                                         kwargs.get('__pub_jid', ''))
    stderr = subprocess.STDOUT if redirect_stderr else subprocess.PIPE
    ret = _run(cmd,
               runas=runas,
               group=group,
               cwd=cwd,
               stdin=stdin,
               stderr=stderr,
               shell=shell,
               python_shell=python_shell,
               env=env,
               clean_env=clean_env,
               prepend_path=prepend_path,
               rstrip=rstrip,
               umask=umask,
               output_encoding=output_encoding,
               output_loglevel=output_loglevel,
               log_callback=log_callback,
               timeout=timeout,
               reset_system_locale=reset_system_locale,
               ignore_retcode=ignore_retcode,
               saltenv=saltenv,
               password=password,
               encoded_cmd=encoded_cmd,
               success_retcodes=success_retcodes,
               **kwargs)

    if hide_output:
        ret['stdout'] = ret['stderr'] = ''
    return ret

def _retcode_quiet(cmd,
                   cwd=None,
                   stdin=None,
                   runas=None,
                   group=None,
                   shell=DEFAULT_SHELL,
                   python_shell=False,
                   env=None,
                   clean_env=False,
                   umask=None,
                   output_encoding=None,
                   log_callback=None,
                   timeout=None,
                   reset_system_locale=True,
                   ignore_retcode=False,
                   saltenv='base',
                   password=None,
                   success_retcodes=None,
                   **kwargs):
    '''
    Helper for running commands quietly for minion startup. Returns same as
    the retcode() function.
    '''
    return retcode(cmd,
                   cwd=cwd,
                   stdin=stdin,
                   runas=runas,
                   group=group,
                   shell=shell,
                   python_shell=python_shell,
                   env=env,
                   clean_env=clean_env,
                   umask=umask,
                   output_encoding=output_encoding,
                   output_loglevel='quiet',
                   log_callback=log_callback,
                   timeout=timeout,
                   reset_system_locale=reset_system_locale,
                   ignore_retcode=ignore_retcode,
                   saltenv=saltenv,
                   password=password,
                   success_retcodes=success_retcodes,
                   **kwargs)

def retcode(cmd,
            cwd=None,
            stdin=None,
            runas=None,
            group=None,
            shell=DEFAULT_SHELL,
            python_shell=None,
            env=None,
            clean_env=False,
            umask=None,
            output_encoding=None,
            output_loglevel='debug',
            log_callback=None,
            timeout=None,
            reset_system_locale=True,
            ignore_retcode=False,
            saltenv='base',
            password=None,
            success_retcodes=None,
            **kwargs):
    '''
    Execute a shell command and return the command's return code.

    :param str cmd: The command to run. ex: ``ls -lart /home``

    :param str cwd: The directory from which to execute the command. Defaults
        to the home directory of the user specified by ``runas`` (or the user
        under which Salt is running if ``runas`` is not specified).

    :param str stdin: A string of standard input can be specified for the
        command to be run using the ``stdin`` parameter. This can be useful in
        cases where sensitive information must be read from standard input.

    :param str runas: Specify an alternate user to run the command. The default
        behavior is to run as the user under which Salt is running. If running
        on a Windows minion you must also use the ``password`` argument, and
        the target user account must be in the Administrators group.

        .. warning::

            For versions 2018.3.3 and above on macosx while using runas,
            to pass special characters to the command you need to escape
            the characters on the shell.

            Example:

            .. code-block:: bash

                cmd.retcode 'echo '\\''h=\\"baz\\"'\\\''' runas=macuser

    :param str password: Windows only. Required when specifying ``runas``. This
        parameter will be ignored on non-Windows platforms.

        .. versionadded:: 2016.3.0

    :param str group: Group to run command as. Not currently supported
      on Windows.

    :param str shell: Specify an alternate shell. Defaults to the system's
        default shell.

    :param bool python_shell: If False, let python handle the positional
        arguments. Set to True to use shell features, such as pipes or
        redirection.

    :param dict env: Environment variables to be set prior to execution.

        .. note::
            When passing environment variables on the CLI, they should be
            passed as the string representation of a dictionary.

            .. code-block:: bash

                salt myminion cmd.retcode 'some command' env='{"FOO": "bar"}'

    :param bool clean_env: Attempt to clean out all other shell environment
        variables and set only those provided in the 'env' argument to this
        function.

    :param bool rstrip: Strip all whitespace off the end of output before it is
        returned.

    :param str umask: The umask (in octal) to use when running the command.

    :param str output_encoding: Control the encoding used to decode the
        command's output.

        .. note::
            This should not need to be used in most cases. By default, Salt
            will try to use the encoding detected from the system locale, and
            will fall back to UTF-8 if this fails. This should only need to be
            used in cases where the output of the command is encoded in
            something other than the system locale or UTF-8.

            To see the encoding Salt has detected from the system locale, check
            the `locale` line in the output of :py:func:`test.versions_report
            <hubblestack.modules.test.versions_report>`.

        .. versionadded:: 2018.3.0

    :param str output_loglevel: Control the loglevel at which the output from
        the command is logged to the minion log.

        .. note::
            The command being run will still be logged at the ``debug``
            loglevel regardless, unless ``quiet`` is used for this value.

    :param bool ignore_retcode: If the exit code of the command is nonzero,
        this is treated as an error condition, and the output from the command
        will be logged to the minion log. However, there are some cases where
        programs use the return code for signaling and a nonzero exit code
        doesn't necessarily mean failure. Pass this argument as ``True`` to
        skip logging the output if the command has a nonzero exit code.

    :param int timeout: A timeout in seconds for the executed process to return.

    :rtype: int
    :rtype: None
    :returns: Return Code as an int or None if there was an exception.

    :param list success_retcodes: This parameter will be allow a list of
        non-zero return codes that should be considered a success.  If the
        return code returned from the run matches any in the provided list,
        the return code will be overridden with zero.

      .. versionadded:: 2019.2.0

    :param bool stdin_raw_newlines: False
        If ``True``, Salt will not automatically convert the characters ``\\n``
        present in the ``stdin`` value to newlines.

      .. versionadded:: 2019.2.0

    CLI Example:

    .. code-block:: bash

        salt '*' cmd.retcode "file /bin/bash"

    A string of standard input can be specified for the command to be run using
    the ``stdin`` parameter. This can be useful in cases where sensitive
    information must be read from standard input.

    .. code-block:: bash

        salt '*' cmd.retcode "grep f" stdin='one\\ntwo\\nthree\\nfour\\nfive\\n'
    '''
    python_shell = _python_shell_default(python_shell,
                                         kwargs.get('__pub_jid', ''))

    ret = _run(cmd,
               runas=runas,
               group=group,
               cwd=cwd,
               stdin=stdin,
               stderr=subprocess.STDOUT,
               shell=shell,
               python_shell=python_shell,
               env=env,
               clean_env=clean_env,
               umask=umask,
               output_encoding=output_encoding,
               output_loglevel=output_loglevel,
               log_callback=log_callback,
               timeout=timeout,
               reset_system_locale=reset_system_locale,
               ignore_retcode=ignore_retcode,
               saltenv=saltenv,
               password=password,
               success_retcodes=success_retcodes,
               **kwargs)
    return ret['retcode']

def run(cmd,
        cwd=None,
        stdin=None,
        runas=None,
        group=None,
        shell=DEFAULT_SHELL,
        python_shell=None,
        env=None,
        clean_env=False,
        rstrip=True,
        umask=None,
        output_encoding=None,
        output_loglevel='debug',
        log_callback=None,
        hide_output=False,
        timeout=None,
        reset_system_locale=True,
        ignore_retcode=False,
        saltenv='base',
        bg=False,
        password=None,
        encoded_cmd=False,
        raise_err=False,
        prepend_path=None,
        success_retcodes=None,
        **kwargs):
    r'''
    Execute the passed command and return the output as a string

    :param str cmd: The command to run. ex: ``ls -lart /home``

    :param str cwd: The directory from which to execute the command. Defaults
        to the home directory of the user specified by ``runas`` (or the user
        under which Salt is running if ``runas`` is not specified).

    :param str stdin: A string of standard input can be specified for the
        command to be run using the ``stdin`` parameter. This can be useful in
        cases where sensitive information must be read from standard input.

    :param str runas: Specify an alternate user to run the command. The default
        behavior is to run as the user under which Salt is running.

        .. warning::

            For versions 2018.3.3 and above on macosx while using runas,
            to pass special characters to the command you need to escape
            the characters on the shell.

            Example:

            .. code-block:: bash

                cmd.run 'echo '\''h=\"baz\"'\''' runas=macuser

    :param str group: Group to run command as. Not currently supported
        on Windows.

    :param str password: Windows only. Required when specifying ``runas``. This
        parameter will be ignored on non-Windows platforms.

        .. versionadded:: 2016.3.0

    :param str shell: Specify an alternate shell. Defaults to the system's
        default shell.

    :param bool python_shell: If ``False``, let python handle the positional
        arguments. Set to ``True`` to use shell features, such as pipes or
        redirection.

    :param bool bg: If ``True``, run command in background and do not await or
        deliver it's results

        .. versionadded:: 2016.3.0

    :param dict env: Environment variables to be set prior to execution.

        .. note::
            When passing environment variables on the CLI, they should be
            passed as the string representation of a dictionary.

            .. code-block:: bash

                salt myminion cmd.run 'some command' env='{"FOO": "bar"}'

    :param bool clean_env: Attempt to clean out all other shell environment
        variables and set only those provided in the 'env' argument to this
        function.

    :param str prepend_path: $PATH segment to prepend (trailing ':' not
        necessary) to $PATH

        .. versionadded:: 2018.3.0

    :param bool rstrip: Strip all whitespace off the end of output before it is
        returned.

    :param str umask: The umask (in octal) to use when running the command.

    :param str output_encoding: Control the encoding used to decode the
        command's output.

        .. note::
            This should not need to be used in most cases. By default, Salt
            will try to use the encoding detected from the system locale, and
            will fall back to UTF-8 if this fails. This should only need to be
            used in cases where the output of the command is encoded in
            something other than the system locale or UTF-8.

            To see the encoding Salt has detected from the system locale, check
            the `locale` line in the output of :py:func:`test.versions_report
            <hubblestack.modules.test.versions_report>`.

        .. versionadded:: 2018.3.0

    :param str output_loglevel: Control the loglevel at which the output from
        the command is logged to the minion log.

        .. note::
            The command being run will still be logged at the ``debug``
            loglevel regardless, unless ``quiet`` is used for this value.

    :param bool ignore_retcode: If the exit code of the command is nonzero,
        this is treated as an error condition, and the output from the command
        will be logged to the minion log. However, there are some cases where
        programs use the return code for signaling and a nonzero exit code
        doesn't necessarily mean failure. Pass this argument as ``True`` to
        skip logging the output if the command has a nonzero exit code.

    :param bool hide_output: If ``True``, suppress stdout and stderr in the
        return data.

        .. note::
            This is separate from ``output_loglevel``, which only handles how
            Salt logs to the minion log.

        .. versionadded:: 2018.3.0

    :param int timeout: A timeout in seconds for the executed process to return.

    :param bool encoded_cmd: Specify if the supplied command is encoded.
        Only applies to shell 'powershell'.

    :param bool raise_err: If ``True`` and the command has a nonzero exit code,
        a CommandExecutionError exception will be raised.

    .. warning::
        This function does not process commands through a shell
        unless the python_shell flag is set to True. This means that any
        shell-specific functionality such as 'echo' or the use of pipes,
        redirection or &&, should either be migrated to cmd.shell or
        have the python_shell=True flag set here.

        The use of python_shell=True means that the shell will accept _any_ input
        including potentially malicious commands such as 'good_command;rm -rf /'.
        Be absolutely certain that you have sanitized your input prior to using
        python_shell=True

    :param list success_retcodes: This parameter will be allow a list of
        non-zero return codes that should be considered a success.  If the
        return code returned from the run matches any in the provided list,
        the return code will be overridden with zero.

      .. versionadded:: 2019.2.0

    :param bool stdin_raw_newlines: False
        If ``True``, Salt will not automatically convert the characters ``\\n``
        present in the ``stdin`` value to newlines.

      .. versionadded:: 2019.2.0

    CLI Example:

    .. code-block:: bash

        salt '*' cmd.run "ls -l | awk '/foo/{print \\$2}'"

    Specify an alternate shell with the shell parameter:

    .. code-block:: bash

        salt '*' cmd.run "Get-ChildItem C:\\ " shell='powershell'

    A string of standard input can be specified for the command to be run using
    the ``stdin`` parameter. This can be useful in cases where sensitive
    information must be read from standard input.

    .. code-block:: bash

        salt '*' cmd.run "grep f" stdin='one\\ntwo\\nthree\\nfour\\nfive\\n'

    If an equal sign (``=``) appears in an argument to a Salt command it is
    interpreted as a keyword argument in the format ``key=val``. That
    processing can be bypassed in order to pass an equal sign through to the
    remote shell command by manually specifying the kwarg:

    .. code-block:: bash

        salt '*' cmd.run cmd='sed -e s/=/:/g'
    '''
    python_shell = _python_shell_default(python_shell,
                                         kwargs.get('__pub_jid', ''))
    ret = _run(cmd,
               runas=runas,
               group=group,
               shell=shell,
               python_shell=python_shell,
               cwd=cwd,
               stdin=stdin,
               stderr=subprocess.STDOUT,
               env=env,
               clean_env=clean_env,
               prepend_path=prepend_path,
               rstrip=rstrip,
               umask=umask,
               output_encoding=output_encoding,
               output_loglevel=output_loglevel,
               log_callback=log_callback,
               timeout=timeout,
               reset_system_locale=reset_system_locale,
               ignore_retcode=ignore_retcode,
               saltenv=saltenv,
               bg=bg,
               password=password,
               encoded_cmd=encoded_cmd,
               success_retcodes=success_retcodes,
               **kwargs)

    log_callback = _check_cb(log_callback)

    lvl = _check_loglevel(output_loglevel)
    if lvl is not None:
        if not ignore_retcode and ret['retcode'] != 0:
            if lvl < LOG_LEVELS['error']:
                lvl = LOG_LEVELS['error']
            msg = (
                'Command \'{0}\' failed with return code: {1}'.format(
                    cmd,
                    ret['retcode']
                )
            )
            log.error(log_callback(msg))
            if raise_err:
                raise CommandExecutionError(
                    log_callback(ret['stdout'] if not hide_output else '')
                )
        log.log(lvl, 'output: %s', log_callback(ret['stdout']))
    return ret['stdout'] if not hide_output else ''
