# -*- coding: utf-8 -*-
'''
For running command line executables with a timeout
'''

import shlex
import subprocess
import threading
import hubblestack.exceptions
import hubblestack.utils.data
import hubblestack.utils.stringutils

class TimedProc(object):
    '''
    Create a TimedProc object, calls subprocess.Popen with passed args and **kwargs
    '''
    def __init__(self, args, **kwargs):

        self.wait = not kwargs.pop('bg', False)
        self.stdin = kwargs.pop('stdin', None)
        self.with_communicate = kwargs.pop('with_communicate', self.wait)
        self.timeout = kwargs.pop('timeout', None)
        self.stdin_raw_newlines = kwargs.pop('stdin_raw_newlines', False)

        # If you're not willing to wait for the process
        # you can't define any stdin, stdout or stderr
        if not self.wait:
            self.stdin = kwargs['stdin'] = None
            self.with_communicate = False
        elif self.stdin is not None:
            if not self.stdin_raw_newlines:
                # Translate a newline submitted as '\n' on the CLI to an actual
                # newline character.
                self.stdin = hubblestack.utils.stringutils.to_bytes(self.stdin.replace('\\n', '\n'))
            kwargs['stdin'] = subprocess.PIPE

        if not self.with_communicate:
            self.stdout = kwargs['stdout'] = None
            self.stderr = kwargs['stderr'] = None

        if self.timeout and not isinstance(self.timeout, (int, float)):
            raise hubblestack.exceptions.TimedProcTimeoutError('Error: timeout {0} must be a number'.format(self.timeout))
        if kwargs.get('shell', False):
            args = hubblestack.utils.data.decode(args, to_str=True)

        try:
            self.process = subprocess.Popen(args, **kwargs)
        except (AttributeError, TypeError):
            if not kwargs.get('shell', False):
                if not isinstance(args, (list, tuple)):
                    try:
                        args = shlex.split(args)
                    except AttributeError:
                        args = shlex.split(str(args))
                str_args = []
                for arg in args:
                    if not isinstance(arg, str):
                        str_args.append(str(arg))
                    else:
                        str_args.append(arg)
                args = str_args
            else:
                if not isinstance(args, (list, tuple, str)):
                    # Handle corner case where someone does a 'cmd.run 3'
                    args = str(args)
            # Ensure that environment variables are strings
            for key, val in iter(kwargs.get('env', {}).items()):
                if not isinstance(val, str):
                    kwargs['env'][key] = str(val)
                if not isinstance(key, str):
                    kwargs['env'][str(key)] = kwargs['env'].pop(key)
            args = hubblestack.utils.data.decode(args)
            self.process = subprocess.Popen(args, **kwargs)
        self.command = args

    def run(self):
        '''
        wait for subprocess to terminate and return subprocess' return code.
        If timeout is reached, throw TimedProcTimeoutError
        '''
        def receive():
            if self.with_communicate:
                self.stdout, self.stderr = self.process.communicate(input=self.stdin)
            elif self.wait:
                self.process.wait()

        if not self.timeout:
            receive()
        else:
            rt = threading.Thread(target=receive)
            rt.start()
            rt.join(self.timeout)
            if rt.isAlive():
                # Subprocess cleanup (best effort)
                self.process.kill()

                def terminate():
                    if rt.isAlive():
                        self.process.terminate()
                threading.Timer(10, terminate).start()
                raise hubblestack.exceptions.TimedProcTimeoutError(
                    '{0} : Timed out after {1} seconds'.format(
                        self.command,
                        str(self.timeout),
                    )
                )
        return self.process.returncode
