# -*- coding: utf-8 -*-
'''
The Salt loader is the core to Salt's plugin system, the loader scans
directories for python loadable code and organizes the code into the
plugin interfaces used by Salt.
'''

import os
import re
import sys
import time
import yaml
import logging
import inspect
import tempfile
import functools
import threading
import traceback
import types

from zipimport import zipimporter

import hubblestack.config
import hubblestack.syspaths
import hubblestack.utils.args
import hubblestack.utils.context
import hubblestack.utils.data
import hubblestack.utils.dictupdate
import hubblestack.utils.files
import hubblestack.utils.lazy
import hubblestack.utils.odict
import hubblestack.utils.platform
import hubblestack.utils.versions

from hubblestack.exceptions import LoaderError
from hubblestack.template import check_render_pipe_str
from hubblestack.utils.decorators import Depends

import hubblestack.syspaths

import importlib.machinery
import importlib.util

import pkg_resources

try:
    from collections.abc import MutableMapping
except ImportError:
    from collections import MutableMapping

log = logging.getLogger(__name__)

HUBBLE_BASE_PATH = os.path.abspath(hubblestack.syspaths.INSTALL_DIR)
LOADED_BASE_NAME = 'hubble.loaded'

MODULE_KIND_SOURCE = 1
MODULE_KIND_COMPILED = 2
MODULE_KIND_EXTENSION = 3
MODULE_KIND_PKG_DIRECTORY = 5
SUFFIXES = []
for suffix in importlib.machinery.EXTENSION_SUFFIXES:
    SUFFIXES.append((suffix, 'rb', MODULE_KIND_EXTENSION))
for suffix in importlib.machinery.SOURCE_SUFFIXES:
    SUFFIXES.append((suffix, 'rb', MODULE_KIND_SOURCE))
for suffix in importlib.machinery.BYTECODE_SUFFIXES:
    SUFFIXES.append((suffix, 'rb', MODULE_KIND_COMPILED))
MODULE_KIND_MAP = {
    MODULE_KIND_SOURCE: importlib.machinery.SourceFileLoader,
    MODULE_KIND_COMPILED: importlib.machinery.SourcelessFileLoader,
    MODULE_KIND_EXTENSION: importlib.machinery.ExtensionFileLoader
}

PY3_PRE_EXT = \
    re.compile(r'\.cpython-{0}{1}(\.opt-[1-9])?'.format(*sys.version_info[:2]))

# Will be set to pyximport module at runtime if cython is enabled in config.
pyximport = None

def _module_dirs(
        opts,
        ext_type,
        tag=None,
        int_type=None,
        ext_dirs=True,
        ext_type_dirs=None,
        base_path=None,
        explain=False,
        ):

    if tag is None:
        tag = ext_type

    # NOTE: this ordering is most authoritative last. if we find a grains
    # module in salt, we want to replace it with the grains module from hubble,
    # so hubble's path should come last.

    ext_types = os.path.join(opts['extension_modules'], ext_type)
    sys_types = os.path.join(base_path or HUBBLE_BASE_PATH, int_type or ext_type)

    hubblestack_type = 'hubblestack_' + (int_type or ext_type)
    files_base_types = os.path.join(base_path or HUBBLE_BASE_PATH, 'files', hubblestack_type)

    ext_type_types = []
    if ext_dirs:
        if tag is not None and ext_type_dirs is None:
            ext_type_dirs = '{0}_dirs'.format(tag)
        if ext_type_dirs in opts:
            ext_type_types.extend(opts[ext_type_dirs])
        for entry_point in pkg_resources.iter_entry_points('hubble.loader', ext_type_dirs):
            try:
                loaded_entry_point = entry_point.load()
                for path in loaded_entry_point():
                    ext_type_types.append(path)
            except Exception as exc:
                log.error("Error getting module directories from %s: %s", _format_entrypoint_target(entry_point), exc)
                log.debug("Full backtrace for module directories error", exc_info=True)

    cli_module_dirs = []
    # The dirs can be any module dir, or a in-tree _{ext_type} dir
    for _dir in opts.get('module_dirs', []):
        # Prepend to the list to match cli argument ordering
        maybe_dir = os.path.join(_dir, ext_type)
        if os.path.isdir(maybe_dir):
            cli_module_dirs.insert(0, maybe_dir)
            continue

        maybe_dir = os.path.join(_dir, '_{0}'.format(ext_type))
        if os.path.isdir(maybe_dir):
            cli_module_dirs.insert(0, maybe_dir)

    as_tuple = (cli_module_dirs, ext_type_types, [files_base_types, ext_types, sys_types])
    log.debug('_module_dirs() => %s', as_tuple)
    if explain:
        return as_tuple
    return cli_module_dirs + ext_type_types + [files_base_types, ext_types, sys_types]


def modules(
        opts,
        context=None,
        utils=None,
        whitelist=None,
        initial_load=False,
        loaded_base_name=None,
        notify=False,
        static_modules=None,
        proxy=None):
    '''
    Load execution modules

    Returns a dictionary of execution modules appropriate for the current
    system by evaluating the __virtual__() function in each module.

    :param dict opts: The Salt options dictionary

    :param dict context: A Salt context that should be made present inside
                            generated modules in __context__

    :param dict utils: Utility functions which should be made available to
                            Salt modules in __utils__. See `utils_dirs` in
                            hubblestack.config for additional information about
                            configuration.

    :param list whitelist: A list of modules which should be whitelisted.
    :param bool initial_load: Deprecated flag! Unused.
    :param str loaded_base_name: A string marker for the loaded base name.
    :param bool notify: Flag indicating that an event should be fired upon
                        completion of module loading.

    .. code-block:: python

        import hubblestack.config
        import hubblestack.loader

        __opts__ = hubblestack.config.get_config('/etc/salt/minion')
        __grains__ = hubblestack.loader.grains(__opts__)
        __opts__['grains'] = __grains__
        __utils__ = hubblestack.loader.utils(__opts__)
        __mods__ = hubblestack.loader.modules(__opts__, utils=__utils__)
        __mods__['test.ping']()
    '''
    # TODO Publish documentation for module whitelisting
    if not whitelist:
        whitelist = opts.get('whitelist_modules', None)
    ret = LazyLoader(
        _module_dirs(opts, 'modules', 'module'),
        opts,
        tag='module',
        pack={'__context__': context, '__utils__': utils, '__proxy__': proxy},
        whitelist=whitelist,
        loaded_base_name=loaded_base_name,
        static_modules=static_modules,
    )

    ret.pack['__mods__'] = ret

    return ret


def returners(opts, functions, whitelist=None, context=None, proxy=None):
    '''
    Returns the returner modules
    '''
    return LazyLoader(
        _module_dirs(opts, 'returners', 'returner'),
        opts,
        tag='returner',
        whitelist=whitelist,
        pack={'__mods__': functions, '__context__': context, '__proxy__': proxy or {}},
    )


def utils(opts, whitelist=None, context=None, proxy=None):
    '''
    Returns the utility modules
    '''
    return LazyLoader(
        _module_dirs(opts, 'utils', ext_type_dirs='utils_dirs'),
        opts,
        tag='utils',
        whitelist=whitelist,
        pack={'__context__': context, '__proxy__': proxy or {}},
    )


def fileserver(opts, backends):
    '''
    Returns the file server modules
    '''
    return LazyLoader(_module_dirs(opts, 'fileserver'),
                      opts,
                      tag='fileserver',
                      whitelist=backends,
                      pack={'__utils__': utils(opts)})


def grain_funcs(opts, proxy=None):
    '''
    Returns the grain functions

      .. code-block:: python

          import hubblestack.config
          import hubblestack.loader

          __opts__ = hubblestack.config.get_config('/etc/salt/minion')
          grainfuncs = hubblestack.loader.grain_funcs(__opts__)
    '''
    return LazyLoader(
        _module_dirs(
            opts,
            'grains',
            'grain',
            ext_type_dirs='grains_dirs',
        ),
        opts,
        tag='grains',
    )


def grains(opts, force_refresh=False, proxy=None):
    '''
    Return the functions for the dynamic grains and the values for the static
    grains.

    Since grains are computed early in the startup process, grains functions
    do not have __mods__ or __proxy__ available.  At proxy-minion startup,
    this function is called with the proxymodule LazyLoader object so grains
    functions can communicate with their controlled device.

    .. code-block:: python

        import hubblestack.config
        import hubblestack.loader

        __opts__ = hubblestack.config.get_config('/etc/salt/minion')
        __grains__ = hubblestack.loader.grains(__opts__)
        print __grains__['id']
    '''
    # Need to re-import hubblestack.config, somehow it got lost when a minion is starting
    import hubblestack.config
    # if we have no grains, lets try loading from disk (TODO: move to decorator?)
    cfn = os.path.join(
        opts['cachedir'],
        'grains.cache.p'
    )

    if opts.get('skip_grains', False):
        return {}
    grains_deep_merge = opts.get('grains_deep_merge', False) is True
    if 'conf_file' in opts:
        pre_opts = {}
        pre_opts.update(hubblestack.config.load_config(
            opts['conf_file'], 'HUBBLE_CONFIG',
            hubblestack.config.DEFAULT_OPTS['conf_file']
        ))
        default_include = pre_opts.get(
            'default_include', opts['default_include']
        )
        include = pre_opts.get('include', [])
        pre_opts.update(hubblestack.config.include_config(
            default_include, opts['conf_file'], verbose=False
        ))
        pre_opts.update(hubblestack.config.include_config(
            include, opts['conf_file'], verbose=True
        ))
        if 'grains' in pre_opts:
            opts['grains'] = pre_opts['grains']
        else:
            opts['grains'] = {}
    else:
        opts['grains'] = {}

    grains_data = {}
    funcs = grain_funcs(opts, proxy=None)
    if force_refresh:  # if we refresh, lets reload grain modules
        funcs.clear()
    # Run core grains
    for key in funcs:
        if not key.startswith('core.'):
            continue
        log.trace('Loading %s grain', key)
        ret = funcs[key]()
        if not isinstance(ret, dict):
            continue
        if grains_deep_merge:
            hubblestack.utils.dictupdate.update(grains_data, ret)
        else:
            grains_data.update(ret)

    # Run the rest of the grains
    for key in funcs:
        if key.startswith('core.') or key == '_errors':
            continue
        try:
            # Grains are loaded too early to take advantage of the injected
            # __proxy__ variable.  Pass an instance of that LazyLoader
            # here instead to grains functions if the grains functions take
            # one parameter.  Then the grains can have access to the
            # proxymodule for retrieving information from the connected
            # device.
            log.trace('Loading %s grain', key)
            parameters = hubblestack.utils.args.get_function_argspec(funcs[key]).args
            kwargs = {}
            if 'proxy' in parameters:
                kwargs['proxy'] = proxy
            if 'grains' in parameters:
                kwargs['grains'] = grains_data
            ret = funcs[key](**kwargs)
        except Exception:
            log.critical(
                'Failed to load grains defined in grain file %s in '
                'function %s, error:\n', key, funcs[key],
                exc_info=True
            )
            continue
        if not isinstance(ret, dict):
            continue
        if grains_deep_merge:
            hubblestack.utils.dictupdate.update(grains_data, ret)
        else:
            grains_data.update(ret)

    grains_data.update(opts['grains'])
    # Write cache if enabled
    if opts.get('grains_cache', False):
        with hubblestack.utils.files.set_umask(0o077):
            try:
                if hubblestack.utils.platform.is_windows():
                    # Late import
                    import hubblestack.modules.cmdmod
                    # Make sure cache file isn't read-only
                    hubblestack.modules.cmdmod._run_quiet('attrib -R "{0}"'.format(cfn))
                with hubblestack.utils.files.fopen(cfn, 'w+b') as fp_:
                    try:
                        serial = hubblestack.payload.Serial(opts)
                        serial.dump(grains_data, fp_)
                    except TypeError as e:
                        log.error('Failed to serialize grains cache: %s', e)
                        raise  # re-throw for cleanup
            except Exception as e:
                log.error('Unable to write to grains cache file %s: %s', cfn, e)
                # Based on the original exception, the file may or may not have been
                # created. If it was, we will remove it now, as the exception means
                # the serialized data is not to be trusted, no matter what the
                # exception is.
                if os.path.isfile(cfn):
                    os.unlink(cfn)

    if grains_deep_merge:
        hubblestack.utils.dictupdate.update(grains_data, opts['grains'])
    else:
        grains_data.update(opts['grains'])
    return hubblestack.utils.data.decode(grains_data, preserve_tuples=True)

def render(opts, functions):
    '''
    Returns the render modules
    '''
    pack = {'__mods__': functions,
            '__grains__': opts.get('grains', {})}
    ret = LazyLoader(
        _module_dirs(
            opts,
            'renderers',
            'render',
            ext_type_dirs='render_dirs',
        ),
        opts,
        tag='render',
        pack=pack,
    )
    rend = FilterDictWrapper(ret, '.render')

    if not check_render_pipe_str(opts['renderer'], rend, opts['renderer_blacklist'], opts['renderer_whitelist']):
        err = ('The renderer {0} is unavailable, this error is often because '
               'the needed software is unavailable'.format(opts['renderer']))
        log.critical(err)
        raise LoaderError(err)
    return rend


def _generate_module(name):
    if name in sys.modules:
        return

    code = "'''Salt loaded {0} parent module'''".format(name.split('.')[-1])
    # ModuleType can't accept a unicode type on PY2
    module = types.ModuleType(str(name))  # future lint: disable=blacklisted-function
    exec(code, module.__dict__)
    sys.modules[name] = module


def _mod_type(module_path):
    if module_path.startswith(HUBBLE_BASE_PATH):
        return 'int'
    return 'ext'


class LazyLoader(hubblestack.utils.lazy.LazyDict):
    '''
    A pseduo-dictionary which has a set of keys which are the
    name of the module and function, delimited by a dot. When
    the value of the key is accessed, the function is then loaded
    from disk and into memory.

    .. note::

        Iterating over keys will cause all modules to be loaded.

    :param list module_dirs: A list of directories on disk to search for modules
    :param dict opts: The salt options dictionary.
    :param str tag: The tag for the type of module to load
    :param func mod_type_check: A function which can be used to verify files
    :param dict pack: A dictionary of function to be packed into modules as they are loaded
    :param list whitelist: A list of modules to whitelist
    :param bool virtual_enable: Whether or not to respect the __virtual__ function when loading modules.
    :param str virtual_funcs: The name of additional functions in the module to call to verify its functionality.
                                If not true, the module will not load.
    :returns: A LazyLoader object which functions as a dictionary. Keys are 'module.function' and values
    are function references themselves which are loaded on-demand.
    # TODO:
        - move modules_max_memory into here
        - singletons (per tag)
    '''

    mod_dict_class = hubblestack.utils.odict.OrderedDict

    def __init__(self,
                 module_dirs,
                 opts=None,
                 tag='module',
                 loaded_base_name=None,
                 mod_type_check=None,
                 pack=None,
                 whitelist=None,
                 virtual_enable=True,
                 static_modules=None,
                 funcname_filter=None,
                 xlate_modnames=None,
                 xlate_funcnames=None,
                 proxy=None,
                 virtual_funcs=None,
                 ):  # pylint: disable=W0231
        '''
        In pack, if any of the values are None they will be replaced with an
        empty context-specific dict
        '''

        self.funcname_filter = funcname_filter
        self.xlate_modnames  = xlate_modnames
        self.xlate_funcnames = xlate_funcnames

        self.pack = {} if pack is None else pack
        if opts is None:
            opts = {}
        threadsafety = not opts.get('multiprocessing')
        self.context_dict = hubblestack.utils.context.ContextDict(threadsafe=threadsafety)
        self.opts = self.__prep_mod_opts(opts)

        self.module_dirs = module_dirs
        self.tag = tag
        self.loaded_base_name = loaded_base_name or LOADED_BASE_NAME
        self.mod_type_check = mod_type_check or _mod_type

        if '__context__' not in self.pack:
            self.pack['__context__'] = None

        for k, v in self.pack.items():
            if v is None:  # if the value of a pack is None, lets make an empty dict
                self.context_dict.setdefault(k, {})
                self.pack[k] = hubblestack.utils.context.NamespacedDictWrapper(self.context_dict, k)

        self.whitelist = whitelist
        self.virtual_enable = virtual_enable
        self.initial_load = True

        # names of modules that we don't have (errors, __virtual__, etc.)
        self.missing_modules = {}  # mapping of name -> error
        self.loaded_modules = {}  # mapping of module_name -> dict_of_functions
        self.loaded_files = set()  # TODO: just remove them from file_mapping?
        self.static_modules = static_modules if static_modules else []

        if virtual_funcs is None:
            virtual_funcs = []
        self.virtual_funcs = virtual_funcs

        self.disabled = set(
            self.opts.get(
                'disable_{0}{1}'.format(
                    self.tag,
                    '' if self.tag[-1] == 's' else 's'
                ),
                []
            )
        )

        # A map of suffix to description for imp
        self.suffix_map = {}
        # A list to determine precedence of extensions
        # Prefer packages (directories) over modules (single files)!
        self.suffix_order = ['']
        for (suffix, mode, kind) in SUFFIXES:
            self.suffix_map[suffix] = (suffix, mode, kind)
            self.suffix_order.append(suffix)

        self._lock = threading.RLock()
        self._refresh_file_mapping()

        super(LazyLoader, self).__init__()  # late init the lazy loader
        # create all of the import namespaces

        for subspace in ('int', 'ext', 'e_int', 'salt'):
            _generate_module('.'.join([self.loaded_base_name, tag]))
            _generate_module('.'.join([self.loaded_base_name, tag, subspace]))

    def __getitem__(self, item):
        '''
        Override the __getitem__ in order to decorate the returned function if we need
        to last-minute inject globals
        '''
        return super(LazyLoader, self).__getitem__(item)

    def __getattr__(self, mod_name):
        '''
        Allow for "direct" attribute access-- this allows jinja templates to
        access things like `hubblestack.test.ping()`
        '''
        if mod_name in ('__getstate__', '__setstate__'):
            return object.__getattribute__(self, mod_name)

        # if we have an attribute named that, lets return it.
        try:
            return object.__getattr__(self, mod_name)  # pylint: disable=no-member
        except AttributeError:
            pass

        # otherwise we assume its jinja template access
        if mod_name not in self.loaded_modules and not self.loaded:
            for name in self._iter_files(mod_name):
                if name in self.loaded_files:
                    continue
                # if we got what we wanted, we are done
                if self._load_module(name) and mod_name in self.loaded_modules:
                    break
        if mod_name in self.loaded_modules:
            return self.loaded_modules[mod_name]
        else:
            raise AttributeError(mod_name)

    def missing_fun_string(self, function_name):
        '''
        Return the error string for a missing function.

        This can range from "not available' to "__virtual__" returned False
        '''
        mod_name = function_name.split('.')[0]
        if mod_name in self.loaded_modules:
            return '\'{0}\' is not available.'.format(function_name)
        else:
            try:
                reason = self.missing_modules[mod_name]
            except KeyError:
                return '\'{0}\' is not available.'.format(function_name)
            else:
                if reason is not None:
                    return '\'{0}\' __virtual__ returned False: {1}'.format(mod_name, reason)
                else:
                    return '\'{0}\' __virtual__ returned False'.format(mod_name)

    def _refresh_file_mapping(self):
        '''
        refresh the mapping of the FS on disk
        '''
        # map of suffix to description for imp
        if self.opts.get('cython_enable', True) is True:
            try:
                global pyximport
                pyximport = __import__('pyximport')  # pylint: disable=import-error
                pyximport.install()
                # add to suffix_map so file_mapping will pick it up
                self.suffix_map['.pyx'] = tuple()
            except ImportError:
                log.info('Cython is enabled in the options but not present '
                    'in the system path. Skipping Cython modules.')
        # Allow for zipimport of modules
        if self.opts.get('enable_zip_modules', True) is True:
            self.suffix_map['.zip'] = tuple()
        # allow for module dirs
        self.suffix_map[''] = ('', '', MODULE_KIND_PKG_DIRECTORY)

        # create mapping of filename (without suffix) to (path, suffix)
        # The files are added in order of priority, so order *must* be retained.
        self.file_mapping = hubblestack.utils.odict.OrderedDict()

        opt_match = []

        def _replace_pre_ext(obj):
            '''
            Hack so we can get the optimization level that we replaced (if
            any) out of the re.sub call below. We use a list here because
            it is a persistent data structure that we will be able to
            access after re.sub is called.
            '''
            opt_match.append(obj)
            return ''

        for mod_dir in self.module_dirs:
            try:
                # Make sure we have a sorted listdir in order to have
                # expectable override results
                files = sorted(
                    x for x in os.listdir(mod_dir) if x != '__pycache__'
                )
            except OSError:
                continue  # Next mod_dir

            try:
                pycache_files = [
                    os.path.join('__pycache__', x) for x in
                    sorted(os.listdir(os.path.join(mod_dir, '__pycache__')))
                ]
            except OSError:
                pass
            else:
                files.extend(pycache_files)

            for filename in files:
                try:
                    dirname, basename = os.path.split(filename)
                    if basename.startswith('_'):
                        # skip private modules
                        # log messages omitted for obviousness
                        continue  # Next filename
                    f_noext, ext = os.path.splitext(basename)
                    f_noext = PY3_PRE_EXT.sub(_replace_pre_ext, f_noext)
                    try:
                        opt_level = int(
                            opt_match.pop().group(1).rsplit('-', 1)[-1]
                        )
                    except (AttributeError, IndexError, ValueError):
                        # No regex match or no optimization level matched
                        opt_level = 0
                    try:
                        opt_index = self.opts['optimization_order'].index(opt_level)
                    except KeyError:
                        log.trace(
                            'Disallowed optimization level %d for module '
                            'name \'%s\', skipping. Add %d to the '
                            '\'optimization_order\' config option if you '
                            'do not want to ignore this optimization '
                            'level.', opt_level, f_noext, opt_level
                        )
                        continue
                    else:
                        # Optimization level not reflected in filename on PY2
                        opt_index = 0

                    # make sure it is a suffix we support
                    if ext not in self.suffix_map:
                        continue  # Next filename
                    if f_noext in self.disabled:
                        log.trace(
                            'Skipping %s, it is disabled by configuration',
                            filename
                        )
                        continue  # Next filename
                    fpath = os.path.join(mod_dir, filename)
                    # if its a directory, lets allow us to load that
                    if ext == '':
                        # is there something __init__?
                        subfiles = os.listdir(fpath)
                        for suffix in self.suffix_order:
                            if '' == suffix:
                                continue  # Next suffix (__init__ must have a suffix)
                            init_file = '__init__{0}'.format(suffix)
                            if init_file in subfiles:
                                break
                        else:
                            continue  # Next filename

                    try:
                        curr_ext = self.file_mapping[f_noext][1]
                        curr_opt_index = self.file_mapping[f_noext][2]
                    except KeyError:
                        pass
                    else:
                        if '' in (curr_ext, ext) and curr_ext != ext:
                            log.error(
                                'Module/package collision: \'%s\' and \'%s\'',
                                fpath,
                                self.file_mapping[f_noext][0]
                            )

                        if ext == '.pyc' and curr_ext == '.pyc':
                            # Check the optimization level
                            if opt_index >= curr_opt_index:
                                # Module name match, but a higher-priority
                                # optimization level was already matched, skipping.
                                continue

                    if not dirname and ext == '.pyc':
                        # On Python 3, we should only load .pyc files from the
                        # __pycache__ subdirectory (i.e. when dirname is not an
                        # empty string).
                        continue

                    # Made it this far - add it
                    self.file_mapping[f_noext] = (fpath, ext, opt_index)

                except OSError:
                    continue
        for smod in self.static_modules:
            f_noext = smod.split('.')[-1]
            self.file_mapping[f_noext] = (smod, '.o', 0)

    def clear(self):
        '''
        Clear the dict
        '''
        with self._lock:
            super(LazyLoader, self).clear()  # clear the lazy loader
            self.loaded_files = set()
            self.missing_modules = {}
            self.loaded_modules = {}
            # if we have been loaded before, lets clear the file mapping since
            # we obviously want a re-do
            if hasattr(self, 'opts'):
                self._refresh_file_mapping()
            self.initial_load = False

    def __prep_mod_opts(self, opts):
        '''
        Strip out of the opts any logger instance
        '''
        if '__grains__' not in self.pack:
            self.context_dict['grains'] = opts.get('grains', {})
            self.pack['__grains__'] = hubblestack.utils.context.NamespacedDictWrapper(self.context_dict, 'grains')

        if '__pillar__' not in self.pack:
            self.context_dict['pillar'] = opts.get('pillar', {})
            self.pack['__pillar__'] = hubblestack.utils.context.NamespacedDictWrapper(self.context_dict, 'pillar')

        mod_opts = {}
        for key, val in list(opts.items()):
            if key == 'logger':
                continue
            mod_opts[key] = val
        return mod_opts

    def _iter_files(self, mod_name):
        '''
        Iterate over all file_mapping files in order of closeness to mod_name
        '''
        # do we have an exact match?
        if mod_name in self.file_mapping:
            yield mod_name

        # do we have a partial match?
        for k in self.file_mapping:
            if mod_name in k:
                yield k

        # anyone else? Bueller?
        for k in self.file_mapping:
            if mod_name not in k:
                yield k

    def _reload_submodules(self, mod):
        submodules = (
            getattr(mod, sname) for sname in dir(mod) if
            isinstance(getattr(mod, sname), mod.__class__)
        )

        # reload only custom "sub"modules
        for submodule in submodules:
            # it is a submodule if the name is in a namespace under mod
            if submodule.__name__.startswith(mod.__name__ + '.'):
                reload_module(submodule)
                self._reload_submodules(submodule)

    def _load_module(self, name):
        mod = None
        fpath, suffix = self.file_mapping[name][:2]
        self.loaded_files.add(name)
        fpath_dirname = os.path.dirname(fpath)
        try:
            sys.path.append(fpath_dirname)
            if fpath_dirname.endswith('__pycache__'):
                sys.path.append( os.path.dirname(fpath_dirname) )
            if suffix == '.pyx':
                mod = pyximport.load_module(name, fpath, tempfile.gettempdir())
            elif suffix == '.o':
                top_mod = __import__(fpath, globals(), locals(), [])
                comps = fpath.split('.')
                if len(comps) < 2:
                    mod = top_mod
                else:
                    mod = top_mod
                    for subname in comps[1:]:
                        mod = getattr(mod, subname)
            elif suffix == '.zip':
                mod = zipimporter(fpath).load_module(name)
            else:
                desc = self.suffix_map[suffix]
                # if it is a directory, we don't open a file
                try:
                    mod_namespace = '.'.join((
                        self.loaded_base_name,
                        self.mod_type_check(fpath),
                        self.tag,
                        name))
                except TypeError:
                    mod_namespace = '{0}.{1}.{2}.{3}'.format(
                        self.loaded_base_name,
                        self.mod_type_check(fpath),
                        self.tag,
                        name)
                if suffix == '':
                    # pylint: disable=no-member
                    # Package directory, look for __init__
                    loader_details = [
                        (importlib.machinery.SourceFileLoader, importlib.machinery.SOURCE_SUFFIXES),
                        (importlib.machinery.SourcelessFileLoader, importlib.machinery.BYTECODE_SUFFIXES),
                        (importlib.machinery.ExtensionFileLoader, importlib.machinery.EXTENSION_SUFFIXES),
                    ]
                    file_finder = importlib.machinery.FileFinder(
                        fpath_dirname,
                        *loader_details
                    )
                    spec = file_finder.find_spec(mod_namespace)
                    if spec is None:
                        raise ImportError()
                    # TODO: Get rid of load_module in favor of
                    # exec_module below. load_module is deprecated, but
                    # loading using exec_module has been causing odd things
                    # with the magic dunders we pack into the loaded
                    # modules, most notably with salt-ssh's __opts__.
                    mod = spec.loader.load_module()
                    # mod = importlib.util.module_from_spec(spec)
                    # spec.loader.exec_module(mod)
                    # pylint: enable=no-member
                    sys.modules[mod_namespace] = mod
                    # reload all submodules if necessary
                    if not self.initial_load:
                        self._reload_submodules(mod)
                else:
                    # pylint: disable=no-member
                    loader = MODULE_KIND_MAP[desc[2]](mod_namespace, fpath)
                    spec = importlib.util.spec_from_file_location(
                        mod_namespace, fpath, loader=loader
                    )
                    if spec is None:
                        raise ImportError()
                    # TODO: Get rid of load_module in favor of
                    # exec_module below. load_module is deprecated, but
                    # loading using exec_module has been causing odd things
                    # with the magic dunders we pack into the loaded
                    # modules, most notably with salt-ssh's __opts__.
                    mod = spec.loader.load_module()
                    #mod = importlib.util.module_from_spec(spec)
                    #spec.loader.exec_module(mod)
                    # pylint: enable=no-member
                    sys.modules[mod_namespace] = mod
        except IOError:
            raise
        except ImportError as exc:
            if 'magic number' in str(exc):
                error_msg = 'Failed to import {0} {1}. Bad magic number. If migrating from Python2 to Python3, remove all .pyc files and try again.'.format(self.tag, name)
                log.warning(error_msg)
                self.missing_modules[name] = error_msg
            log.debug(
                'Failed to import %s %s:\n',
                self.tag, name, exc_info=True
            )
            self.missing_modules[name] = exc
            return False
        except Exception as error:
            log.error(
                'Failed to import %s %s, this is due most likely to a '
                'syntax error:\n', self.tag, name, exc_info=True
            )
            self.missing_modules[name] = error
            return False
        except SystemExit as error:
            try:
                fn_, _, caller, _ = traceback.extract_tb(sys.exc_info()[2])[-1]
            except Exception:
                pass
            else:
                tgt_fn = os.path.join('salt', 'utils', 'process.py')
                if fn_.endswith(tgt_fn) and '_handle_signals' in caller:
                    # Race conditon, SIGTERM or SIGINT received while loader
                    # was in process of loading a module. Call sys.exit to
                    # ensure that the process is killed.
                    sys.exit(0)
            log.error(
                'Failed to import %s %s as the module called exit()\n',
                self.tag, name, exc_info=True
            )
            self.missing_modules[name] = error
            return False
        finally:
            sys.path.remove(fpath_dirname)

        if hasattr(mod, '__opts__'):
            mod.__opts__.update(self.opts)
        else:
            mod.__opts__ = self.opts

        # pack whatever other globals we were asked to
        for p_name, p_value in self.pack.items():
            setattr(mod, p_name, p_value)

        module_name = mod.__name__.rsplit('.', 1)[-1]
        if callable(self.xlate_modnames):
            module_name = self.xlate_modnames([module_name], name, fpath, suffix, mod, mode='module_name')
            name        = self.xlate_modnames([name], name, fpath, suffix, mod, mode='name')

        # Call a module's initialization method if it exists
        module_init = getattr(mod, '__init__', None)
        if inspect.isfunction(module_init):
            try:
                module_init(self.opts)
            except TypeError as e:
                log.error(e)
            except Exception:
                err_string = '__init__ failed'
                log.debug(
                    'Error loading %s.%s: %s',
                    self.tag, module_name, err_string, exc_info=True
                )
                self.missing_modules[module_name] = err_string
                self.missing_modules[name] = err_string
                return False

        # if virtual modules are enabled, we need to look for the
        # __virtual__() function inside that module and run it.
        if self.virtual_enable:
            virtual_funcs_to_process = ['__virtual__'] + self.virtual_funcs
            for virtual_func in virtual_funcs_to_process:
                virtual_ret, module_name, virtual_err, virtual_aliases = \
                    self._process_virtual(mod, module_name, virtual_func)
                if virtual_err is not None:
                    log.trace(
                        'Error loading %s.%s: %s',
                        self.tag, module_name, virtual_err
                    )

                # if _process_virtual returned a non-True value then we are
                # supposed to not process this module
                if virtual_ret is not True and module_name not in self.missing_modules:
                    # If a module has information about why it could not be loaded, record it
                    self.missing_modules[module_name] = virtual_err
                    self.missing_modules[name] = virtual_err
                    return False
        else:
            virtual_aliases = ()

        if getattr(mod, '__load__', False) is not False:
            log.info(
                'The functions from module \'%s\' are being loaded from the '
                'provided __load__ attribute', module_name
            )

        # If we had another module by the same virtual name, we should put any
        # new functions under the existing dictionary.
        mod_names = [module_name] + list(virtual_aliases)
        if callable(self.xlate_modnames):
            mod_names = self.xlate_modnames(mod_names, name, fpath, suffix, mod, mode='mod_names')
        mod_dict = dict((
            (x, self.loaded_modules.get(x, self.mod_dict_class()))
            for x in mod_names
        ))

        for attr in getattr(mod, '__load__', dir(mod)):
            if attr.startswith('_'):
                # private functions are skipped
                continue
            func = getattr(mod, attr)
            if not inspect.isfunction(func) and not isinstance(func, functools.partial):
                # Not a function!? Skip it!!!
                continue
            if callable(self.funcname_filter) and not self.funcname_filter(attr, mod):
                # rejected by filter
                continue
            # Let's get the function name.
            # If the module has the __func_alias__ attribute, it must be a
            # dictionary mapping in the form of(key -> value):
            #   <real-func-name> -> <desired-func-name>
            #
            # It default's of course to the found callable attribute name
            # if no alias is defined.
            funcname = getattr(mod, '__func_alias__', {}).get(attr, attr)
            for tgt_mod in mod_names:
                try:
                    full_funcname = '.'.join((tgt_mod, funcname))
                except TypeError:
                    full_funcname = '{0}.{1}'.format(tgt_mod, funcname)
                if callable(self.xlate_funcnames):
                    funcname, full_funcname = self.xlate_funcnames(
                        name, fpath, suffix, tgt_mod, funcname, full_funcname, mod, func)
                # Save many references for lookups
                # Careful not to overwrite existing (higher priority) functions
                if full_funcname not in self._dict:
                    self._dict[full_funcname] = func
                if funcname not in mod_dict[tgt_mod]:
                    setattr(mod_dict[tgt_mod], funcname, func)
                    mod_dict[tgt_mod][funcname] = func
                    self._apply_outputter(func, mod)

        # enforce depends
        try:
            Depends.enforce_dependencies(self._dict, self.tag, name)
        except RuntimeError as exc:
            log.info(
                'Depends.enforce_dependencies() failed for the following '
                'reason: %s', exc
            )

        for tgt_mod in mod_names:
            self.loaded_modules[tgt_mod] = mod_dict[tgt_mod]
        return True

    def _load(self, key):
        '''
        Load a single item if you have it
        '''
        # if the key doesn't have a '.' then it isn't valid for this mod dict
        if not isinstance(key, str):
            raise KeyError('The key must be a string.')
        if '.' not in key:
            raise KeyError('The key \'{0}\' should contain a \'.\''.format(key))
        mod_name, _ = key.split('.', 1)
        with self._lock:
            # It is possible that the key is in the dictionary after
            # acquiring the lock due to another thread loading it.
            if mod_name in self.missing_modules or key in self._dict:
                return True
            # if the modulename isn't in the whitelist, don't bother
            if self.whitelist and mod_name not in self.whitelist:
                log.error(
                    'Failed to load function %s because its module (%s) is '
                    'not in the whitelist: %s', key, mod_name, self.whitelist
                )
                raise KeyError(key)

            def _inner_load(mod_name):
                for name in self._iter_files(mod_name):
                    if name in self.loaded_files:
                        continue
                    # if we got what we wanted, we are done
                    if self._load_module(name) and key in self._dict:
                        return True
                return False

            # try to load the module
            ret = None
            reloaded = False
            # re-scan up to once, IOErrors or a failed load cause re-scans of the
            # filesystem
            while True:
                try:
                    ret = _inner_load(mod_name)
                    if not reloaded and ret is not True:
                        self._refresh_file_mapping()
                        reloaded = True
                        continue
                    break
                except IOError:
                    if not reloaded:
                        self._refresh_file_mapping()
                        reloaded = True
                    continue

        return ret

    def _load_all(self):
        '''
        Load all of them
        '''
        with self._lock:
            for name in self.file_mapping:
                if name in self.loaded_files or name in self.missing_modules:
                    continue
                self._load_module(name)

            self.loaded = True

    def reload_modules(self):
        with self._lock:
            self.loaded_files = set()
            self._load_all()

    def _apply_outputter(self, func, mod):
        '''
        Apply the __outputter__ variable to the functions
        '''
        if hasattr(mod, '__outputter__'):
            outp = mod.__outputter__
            if func.__name__ in outp:
                func.__outputter__ = outp[func.__name__]

    def _process_virtual(self, mod, module_name, virtual_func='__virtual__'):
        '''
        Given a loaded module and its default name determine its virtual name

        This function returns a tuple. The first value will be either True or
        False and will indicate if the module should be loaded or not (i.e. if
        it threw and exception while processing its __virtual__ function). The
        second value is the determined virtual name, which may be the same as
        the value provided.

        The default name can be calculated as follows::

            module_name = mod.__name__.rsplit('.', 1)[-1]
        '''

        # The __virtual__ function will return either a True or False value.
        # If it returns a True value it can also set a module level attribute
        # named __virtualname__ with the name that the module should be
        # referred to as.
        #
        # This allows us to have things like the pkg module working on all
        # platforms under the name 'pkg'. It also allows for modules like
        # augeas_cfg to be referred to as 'augeas', which would otherwise have
        # namespace collisions. And finally it allows modules to return False
        # if they are not intended to run on the given platform or are missing
        # dependencies.
        virtual_aliases = getattr(mod, '__virtual_aliases__', tuple())
        try:
            error_reason = None
            if hasattr(mod, '__virtual__') and inspect.isfunction(mod.__virtual__):
                try:
                    start = time.time()
                    virtual = getattr(mod, virtual_func)()
                    if isinstance(virtual, tuple):
                        error_reason = virtual[1]
                        virtual = virtual[0]
                    if self.opts.get('virtual_timer', False):
                        end = time.time() - start
                        msg = 'Virtual function took {0} seconds for {1}'.format(
                                end, module_name)
                        log.warning(msg)
                except Exception as exc:
                    error_reason = (
                        'Exception raised when processing __virtual__ function'
                        ' for {0}. Module will not be loaded: {1}'.format(
                            mod.__name__, exc))
                    log.error(error_reason, exc_info_on_loglevel=logging.DEBUG)
                    virtual = None
                # Get the module's virtual name
                virtualname = getattr(mod, '__virtualname__', virtual)
                if not virtual:
                    # if __virtual__() evaluates to False then the module
                    # wasn't meant for this platform or it's not supposed to
                    # load for some other reason.

                    # Some modules might accidentally return None and are
                    # improperly loaded
                    if virtual is None:
                        log.warning(
                            '%s.__virtual__() is wrongly returning `None`. '
                            'It should either return `True`, `False` or a new '
                            'name. If you\'re the developer of the module '
                            '\'%s\', please fix this.', mod.__name__, module_name
                        )

                    return (False, module_name, error_reason, virtual_aliases)

                # At this point, __virtual__ did not return a
                # boolean value, let's check for deprecated usage
                # or module renames
                if virtual is not True and module_name != virtual:
                    # The module is renaming itself. Updating the module name
                    # with the new name
                    log.trace('Loaded %s as virtual %s', module_name, virtual)

                    if not hasattr(mod, '__virtualname__'):
                        hubblestack.utils.versions.warn_until(
                            'Hydrogen',
                            'The \'{0}\' module is renaming itself in its '
                            '__virtual__() function ({1} => {2}). Please '
                            'set it\'s virtual name as the '
                            '\'__virtualname__\' module attribute. '
                            'Example: "__virtualname__ = \'{2}\'"'.format(
                                mod.__name__,
                                module_name,
                                virtual
                            )
                        )

                    if virtualname != virtual:
                        # The __virtualname__ attribute does not match what's
                        # being returned by the __virtual__() function. This
                        # should be considered an error.
                        log.error(
                            'The module \'%s\' is showing some bad usage. Its '
                            '__virtualname__ attribute is set to \'%s\' yet the '
                            '__virtual__() function is returning \'%s\'. These '
                            'values should match!',
                            mod.__name__, virtualname, virtual
                        )

                    module_name = virtualname

                # If the __virtual__ function returns True and __virtualname__
                # is set then use it
                elif virtual is True and virtualname != module_name:
                    if virtualname is not True:
                        module_name = virtualname

        except KeyError:
            # Key errors come out of the virtual function when passing
            # in incomplete grains sets, these can be safely ignored
            # and logged to debug, still, it includes the traceback to
            # help debugging.
            log.error('Failed to LazyLoad "%s"', module_name, exc_info=True)

        except Exception:
            # If the module throws an exception during __virtual__()
            # then log the information and continue to the next.
            log.error(
                'Failed to read the virtual function for %s: %s',
                self.tag, module_name, exc_info=True
            )
            return (False, module_name, error_reason, virtual_aliases)

        return (True, module_name, None, virtual_aliases)

class FilterDictWrapper(MutableMapping):
    '''
    Create a dict which wraps another dict with a specific key suffix on get

    This is to replace "filter_load"
    '''
    def __init__(self, d, suffix):
        self._dict = d
        self.suffix = suffix

    def __setitem__(self, key, val):
        self._dict[key] = val

    def __delitem__(self, key):
        del self._dict[key]

    def __getitem__(self, key):
        return self._dict[key + self.suffix]

    def __len__(self):
        return len(self._dict)

    def __iter__(self):
        for key in self._dict:
            if key.endswith(self.suffix):
                yield key.replace(self.suffix, '')


def matchers(opts):
    '''
    Return the matcher services plugins
    '''
    return LazyLoader(
        _module_dirs(opts, 'matchers'),
        opts,
        tag='matchers'
    )

def _nova_funcname_filter(funcname, mod):
    """
    reject function names that aren't "audit"

    args:
      mod :- the actual imported module (allowing mod.__file__ examination, etc)
      funcname :- the attribute name as given by dir(mod)

    return:
        True :- sure, we can provide this function
        False :- skip this one
    """
    if funcname == 'audit':
        return True
    return False

def _nova_xlate_modnames(mod_names, name, fpath, suffix, mod, mode='mod_names'):
    """
        Translate (xlate) "service" into "/service"

        args:
            name   :- the name of the module we're loading (e.g., 'service')
            fpath  :- the file path of the module we're loading
            suffix :- the suffix of the module we're loading (e.g., '.pyc', usually)
            mod    :- the actual imported module (allowing mod.__file__ examination)
            mode   :- the name of the load_module variable being translated

        return:
            either a list of new names (for "mod_names") or a single new name
            (for "name" and "module_name")
    """

    new_modname = '/' + name

    if mode in ("module_name", "name"):
        return new_modname
    return [ new_modname ]

def _nova_xlate_funcnames(name, fpath, suffix, tgt_mod, funcname, full_funcname, mod, func):
    """
    Translate (xlate) "service.audit" into "/service.py"

    args:
        name          :- the name of the module we're loading (e.g., 'service')
        fpath         :- the file path of the module we're loading
        suffix        :- the suffix of the module we're loading (e.g., '.pyc', usually)
        tgt_mod       :- the current virtual name of the module we're loading (e.g., 'service')
        funcname      :- the function name we're maping (e.g., 'audit')
        full_funcname :- the LazyLoader key format item (e.g., 'service.audit')
        mod           :- the actual imported module (allowing mod.__file__ examination)
        func          :- the actual function being mapped (allowing func.__name__)

    return:
        funcname, full_funcname

        The old NovaLazyLoader's behavior can be mimicked without altering the
        LazyLoader (very much) by simply pretending tgt_mod='/service',
        funcname='py' and full_funcname='/service.py'.
    """
    new_funcname = suffix[1:]
    if new_funcname == 'pyc':
        new_funcname = 'py'
    return new_funcname, '.'.join([name, new_funcname])

def nova(hubble_dir, opts, modules, context=None):
    '''
    Return a nova (!lazy) loader.

    This does return a LazyLoader, but hubble.audit module always iterates the
    keys forcing a full load, which somewhat defeates the purpose of using the
    LazyLoader object at all.

    nova() also populates loader.__data__ and loader.__missing_data__ for
    backwards compatibility purposes but omits some overlapping functions that
    were essentially unnecessary.

    Originally hubble.audit used a special NovaLazyLoader that was intended to
    make everything more readable but in fact only fragmented the codebase and
    obsfucated the purpose and function of the new data elements it introduced.

    The loader functions and file_mapping functions of the loader were also
    hopelessly mixed up with the yaml data loaders for no apparent reason.

    Presumably the original intent was to be able to use expressions like
    __nova__['/cis/debian-9-whatever.yaml'] to access those data elements;
    but this wasn't actually used, apparently favoring the form:
    __nova__.__data__['/cis/whatever.yaml'] instead.

    The __nova__.__data__['/whatever.yaml'] format is retained, but the
    file_mapping['/whatever.yaml'] and load_module('whatever') functionality is
    not. This means that anywhere refresh_filemapping() is expected to refresh
    yaml on disk will no-longer do so. Interestingly, it didn't seem to work
    before anyway, which seems to be the reason for the special sync() section
    of the hubble.audit.

    '''

    loader = LazyLoader(
        _module_dirs(opts, 'nova'),
        opts,
        tag='nova',
        funcname_filter=_nova_funcname_filter,
        xlate_modnames=_nova_xlate_modnames,
        xlate_funcnames=_nova_xlate_funcnames,
        pack={ '__context__': context, '__mods__': modules }
    )

    loader.__data__ = d = dict()
    loader.__missing_data__ = md = dict()

    for mod_dir in hubble_dir:
        for path, _, filenames in os.walk(mod_dir):
            for filename in filenames:
                pathname = os.path.join(path, filename)
                name = pathname[len(mod_dir):]
                if filename.endswith('.yaml'):
                    try:
                        with open(pathname, 'r') as fh:
                            d[name] = yaml.safe_load(fh)
                    except Exception as exc:
                        md[name] = str(exc)
                        log.exception('Error loading yaml from %s', pathnmame)
    return loader
