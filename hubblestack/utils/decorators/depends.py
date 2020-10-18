#!/usr/bin/env python
# coding: utf-8

import inspect
import logging
from collections import defaultdict

log = logging.getLogger(__name__)

class Depends(object):
    '''
    This decorator will check the module when it is loaded and check that the
    dependencies passed in are in the globals of the module. If not, it will
    cause the function to be unloaded (or replaced).
    '''
    # kind -> Dependency -> list of things that depend on it
    dependency_dict = defaultdict(lambda: defaultdict(dict))

    def __init__(self, *dependencies, **kwargs):
        '''
        The decorator is instantiated with a list of dependencies (string of
        global name)

        An example use of this would be:

        .. code-block:: python

            @depends('modulename')
            def test():
                return 'foo'

            OR

            @depends('modulename', fallback_function=function)
            def test():
                return 'foo'

        .. code-block:: python

        This can also be done with the retcode of a command, using the
        ``retcode`` argument:

            @depends('/opt/bin/check_cmd', retcode=0)
            def test():
                return 'foo'

        It is also possible to check for any nonzero retcode using the
        ``nonzero_retcode`` argument:

            @depends('/opt/bin/check_cmd', nonzero_retcode=True)
            def test():
                return 'foo'

        .. note::
            The command must be formatted as a string, not a list of args.
            Additionally, I/O redirection and other shell-specific syntax are
            not supported since this uses shell=False when calling
            subprocess.Popen().

        '''
        log.trace(
            'Depends decorator instantiated with dep list of %s and kwargs %s',
            dependencies, kwargs
        )
        self.dependencies = dependencies
        self.params = kwargs

    def __call__(self, function):
        '''
        The decorator is "__call__"d with the function, we take that function
        and determine which module and function name it is to store in the
        class wide dependency_dict
        '''
        try:
            # This inspect call may fail under certain conditions in the loader.
            # Possibly related to a Python bug here:
            # http://bugs.python.org/issue17735
            frame = inspect.stack()[1][0]
            # due to missing *.py files under esky we cannot use inspect.getmodule
            # module name is something like salt.loaded.int.modules.test
            _, kind, mod_name = frame.f_globals['__name__'].rsplit('.', 2)
            fun_name = function.__name__
            for dep in self.dependencies:
                self.dependency_dict[kind][dep][(mod_name, fun_name)] = (frame, self.params)
        except Exception as exc:
            log.exception(
                'Exception encountered when attempting to inspect frame in '
                'dependency decorator'
            )
        return function

    @staticmethod
    def run_command(dependency, mod_name, func_name):
        full_name = '{0}.{1}'.format(mod_name, func_name)
        log.trace('Running \'%s\' for \'%s\'', dependency, full_name)
        if IS_WINDOWS:
            args = salt.utils.args.shlex_split(dependency, posix=False)
        else:
            args = salt.utils.args.shlex_split(dependency)
        log.trace('Command after shlex_split: %s', args)
        proc = subprocess.Popen(args,
                                shell=False,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        output = proc.communicate()[0]
        retcode = proc.returncode
        log.trace('Output from \'%s\': %s', dependency, output)
        log.trace('Retcode from \'%s\': %d', dependency, retcode)
        return retcode

    @classmethod
    def enforce_dependencies(cls, functions, kind, tgt_mod):
        '''
        This is a class global method to enforce the dependencies that you
        currently know about.
        It will modify the "functions" dict and remove/replace modules that
        are missing dependencies.
        '''
        for dependency, dependent_dict in cls.dependency_dict[kind].items():
            for (mod_name, func_name), (frame, params) in dependent_dict.items():
                if mod_name != tgt_mod:
                    continue
                if 'retcode' in params or 'nonzero_retcode' in params:
                    try:
                        retcode = cls.run_command(dependency, mod_name, func_name)
                    except OSError as exc:
                        if exc.errno == errno.ENOENT:
                            log.trace(
                                'Failed to run command %s, %s not found',
                                dependency, exc.filename
                            )
                        else:
                            log.trace(
                                'Failed to run command \'%s\': %s', dependency, exc
                            )
                        retcode = -1

                    if 'retcode' in params:
                        if params['retcode'] == retcode:
                            continue

                    elif 'nonzero_retcode' in params:
                        if params['nonzero_retcode']:
                            if retcode != 0:
                                continue
                        else:
                            if retcode == 0:
                                continue

                # check if dependency is loaded
                elif dependency is True:
                    log.trace(
                        'Dependency for %s.%s exists, not unloading',
                        mod_name, func_name
                    )
                    continue

                # check if you have the dependency
                elif dependency in frame.f_globals \
                        or dependency in frame.f_locals:
                    log.trace(
                        'Dependency (%s) already loaded inside %s, skipping',
                        dependency, mod_name
                    )
                    continue

                log.trace(
                    'Unloading %s.%s because dependency (%s) is not met',
                    mod_name, func_name, dependency
                )
                # if not, unload the function
                if frame:
                    try:
                        func_name = frame.f_globals['__func_alias__'][func_name]
                    except (AttributeError, KeyError):
                        pass

                    mod_key = '{0}.{1}'.format(mod_name, func_name)

                    # if we don't have this module loaded, skip it!
                    if mod_key not in functions:
                        continue

                    try:
                        fallback_function = params.get('fallback_function')
                        if fallback_function is not None:
                            functions[mod_key] = fallback_function
                        else:
                            del functions[mod_key]
                    except AttributeError:
                        # we already did???
                        log.trace('%s already removed, skipping', mod_key)
                        continue


depends = Depends
