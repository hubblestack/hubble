# -*- coding: utf-8 -*-
'''
Watch files and translate the changes into salt events

:depends:   - pyinotify Python module >= 0.9.5

:Caution:   Using generic mask options like open, access, ignored, and
            closed_nowrite with reactors can easily cause the reactor
            to loop on itself. To mitigate this behavior, consider
            setting the `disable_during_state_run` flag to `True` in
            the beacon configuration.

'''
# Import Python libs
from __future__ import absolute_import
import collections
import fnmatch
import os
import re
import yaml
import time
from salt.exceptions import CommandExecutionError

# Import salt libs
import salt.ext.six
import salt.loader
import salt.utils.platform

# Import third party libs
try:
    import pyinotify
    HAS_PYINOTIFY = True
    DEFAULT_MASK = pyinotify.IN_CREATE | pyinotify.IN_DELETE | pyinotify.IN_MODIFY
    MASKS = {}
    for var in dir(pyinotify):
        if var.startswith('IN_'):
            key = var[3:].lower()
            MASKS[key] = getattr(pyinotify, var)
except ImportError:
    HAS_PYINOTIFY = False
    DEFAULT_MASK = None

__virtualname__ = 'pulsar'
CONFIG = None
CONFIG_STALENESS = 0
FILE_WATCH = dict()

import logging
log = logging.getLogger(__name__)


def __virtual__():
    if salt.utils.platform.is_windows():
        return False, 'This module only works on Linux'
    return True


def _get_mask(mask):
    '''
    Return the int that represents the mask
    '''
    return MASKS.get(mask, 0)


def _enqueue(revent):
    '''
    Enqueue the event
    '''
    __context__['pulsar.queue'].append(revent)


def _get_notifier():
    '''
    Check the context for the notifier and construct it if not present
    '''
    if 'pulsar.notifier' not in __context__:
        __context__['pulsar.queue'] = collections.deque()
        wm = pyinotify.WatchManager()
        __context__['pulsar.notifier'] = pyinotify.Notifier(wm, _enqueue)
    return __context__['pulsar.notifier']

def _preprocess_excludes(excludes):
    '''
    Wrap excludes in simple decision curry functions.
    '''

    # silently discard non-list excludes
    if not isinstance(excludes, (list,tuple)) or not excludes:
        return lambda x: False

    # wrap whatever in a decision problem
    def re_wrapper(robj):
        # log.debug('wrapping re {0}'.format(robj.pattern))
        def _wrapped(val):
            return bool(robj.search(val))
        return _wrapped
    def fn_wrapper(rpat):
        # log.debug('wrapping fnmatch {0}'.format(rpat))
        def _wrapped(val):
            return bool(fnmatch.fnmatch(rpat, val))
        return _wrapped
    def str_wrapper(rstr):
        # log.debug('wrapping strmatch {0}'.format(rstr))
        def _wrapped(val):
            return bool( val.startswith(rstr) )
        return _wrapped

    # figure out what to wrap things with
    the_list = []
    for e in excludes:
        if isinstance(e,dict):
            if e.values()[0].get('regex'):
                r = e.keys()[0]
                try:
                    c = re.compile(r)
                    the_list.append(re_wrapper(c))
                except:
                    log.warn('Failed to compile regex: {0}'.format(r))
                continue
            else:
                e = e.keys()[0]
        if '*' in e:
            the_list.append(fn_wrapper(e))
        else:
            the_list.append(str_wrapper(e))

    # finally, wrap the whole decision set in a decision wrapper
    def _final(val):
        for i in the_list:
            if i( val ):
                return True
        return False
    time.sleep(2)
    return _final

class delta_t(object):
    def __init__(self):
        self.mark('top')

    def mark(self,name):
        if name.startswith('_'):
            raise Exception("bad mark name")
        t = time.time()
        def _x(self):
            return time.time() - t
        setattr(type(self),name,property(_x))


def process(configfile='salt://hubblestack_pulsar/hubblestack_pulsar_config.yaml',
            verbose=False):
    '''
    Watch the configured files

    Example pillar config

    .. code-block:: yaml

        beacons:
          pulsar:
            paths:
              - /var/cache/salt/minion/files/base/hubblestack_pulsar/hubblestack_pulsar_config.yaml
            refresh_interval: 300
            verbose: False

    Example yaml config on fileserver (targeted by pillar)

    .. code-block:: yaml

        /path/to/file/or/dir:
          mask:
            - open
            - create
            - close_write
          recurse: True
          auto_add: True
          exclude:
            - /path/to/file/or/dir/exclude1
            - /path/to/file/or/dir/exclude2
            - /path/to/file/or/dir/regex[\d]*$:
                regex: True
        return:
          splunk:
            batch: True
          slack:
            batch: False  # overrides the global setting
        checksum: sha256
        stats: True
        batch: True

    Note that if `batch: True`, the configured returner must support receiving
    a list of events, rather than single one-off events.

    The mask list can contain the following events (the default mask is create,
    delete, and modify):

    * access            - File accessed
    * attrib            - File metadata changed
    * close_nowrite     - Unwritable file closed
    * close_write       - Writable file closed
    * create            - File created in watched directory
    * delete            - File deleted from watched directory
    * delete_self       - Watched file or directory deleted
    * modify            - File modified
    * moved_from        - File moved out of watched directory
    * moved_to          - File moved into watched directory
    * move_self         - Watched file moved
    * open              - File opened

    The mask can also contain the following options:

    * dont_follow       - Don't dereference symbolic links
    * excl_unlink       - Omit events for children after they have been unlinked
    * oneshot           - Remove watch after one event
    * onlydir           - Operate only if name is directory

    recurse:
      Recursively watch directories under the named directory
    auto_add:
      Python inotify option, meaning: automatically start watching new
      directories that are created in a watched directory
    watch_new_files:
      when a new file is created in a watched dir, add a watch on the file
      (implied by watch_files below)
    watch_files:
      add explicit watches on all files (except excluded) under the named directory
    exclude:
      Exclude directories or files from triggering events in the watched directory.
      Can use regex if regex is set to True

    If pillar/grains/minion config key `hubblestack:pulsar:maintenance` is set to
    True, then changes will be discarded.
    '''
    if not HAS_PYINOTIFY:
        log.debug('Not running beacon pulsar. No python-inotify installed.')
        return []
    config = __opts__.get('pulsar', {})
    if isinstance(configfile, list):
        config['paths'] = configfile
    else:
        config['paths'] = [configfile]
    config['verbose'] = verbose
    global CONFIG_STALENESS
    global CONFIG
    if config.get('verbose'):
        log.debug('Pulsar beacon called.')
        log.debug('Pulsar beacon config from pillar:\n{0}'.format(config))
    ret = []
    notifier = _get_notifier()
    wm = notifier._watch_manager
    update_watches = False

    # Get config(s) from salt fileserver if we don't have them already
    if CONFIG and CONFIG_STALENESS < config.get('refresh_interval', 300):
        CONFIG_STALENESS += 1
        CONFIG.update(config)
        CONFIG['verbose'] = config.get('verbose')
        config = CONFIG
    else:
        if config.get('verbose'):
            log.debug('No cached config found for pulsar, retrieving fresh from fileserver.')
        new_config = config
        if isinstance(config.get('paths'), list):
            for path in config['paths']:
                if 'salt://' in path:
                    path = __salt__['cp.cache_file'](path)
                if os.path.isfile(path):
                    with open(path, 'r') as f:
                        new_config = _dict_update(new_config,
                                                  yaml.safe_load(f),
                                                  recursive_update=True,
                                                  merge_lists=True)
                else:
                    log.error('Path {0} does not exist or is not a file'.format(path))
        else:
            log.error('Pulsar beacon \'paths\' data improperly formatted. Should be list of paths')

        new_config.update(config)
        config = new_config
        CONFIG_STALENESS = 0
        CONFIG = config
        update_watches = True

    if config.get('verbose'):
        log.debug('Pulsar beacon config (compiled from config list):\n{0}'.format(config))

    dt = delta_t()

    # Read in existing events
    if notifier.check_events(1):
        notifier.read_events()
        notifier.process_events()
        queue = __context__['pulsar.queue']
        if config.get('verbose'):
            log.debug('Pulsar found {0} inotify events.'.format(len(queue)))
        while queue:
            event = queue.popleft()
            if event.maskname == 'IN_Q_OVERFLOW':
                log.warn('Your inotify queue is overflowing.')
                log.warn('Fix by increasing /proc/sys/fs/inotify/max_queued_events')
                continue

            # Find the matching path in config
            path = event.path
            while path != '/':
                if path in config:
                    break
                path = os.path.dirname(path)

            # Get pathname
            # XXX: we try/except to get the pathname, then ignore pathname and use event.pathname below
            try:
                pathname = event.pathname
            except NameError:
                pathname = path

            excludes = _preprocess_excludes( config[path].get('exclude') )
            _append = not excludes(pathname)
            if _append:
                config_path = config['paths'][0]
                pulsar_config = config_path[config_path.rfind('/') + 1:len(config_path)]
                sub = {'tag': event.path,
                       'path': event.pathname,
                       'change': event.maskname,
                       'name': event.name,
                       'pulsar_config': pulsar_config}

                if config.get('checksum', False) and os.path.isfile(pathname):
                    sum_type = config['checksum']
                    if not isinstance(sum_type, salt.ext.six.string_types):
                        sum_type = 'sha256'
                    sub['checksum'] = __salt__['file.get_hash'](pathname, sum_type)
                    sub['checksum_type'] = sum_type
                if config.get('stats', False):
                    if os.path.exists(pathname):
                        sub['stats'] = __salt__['file.stats'](pathname)
                    else:
                        sub['stats'] = {}

                ret.append(sub)

                if not event.mask & pyinotify.IN_ISDIR:
                    if event.mask & pyinotify.IN_CREATE:
                        watch_this = config[path].get('watch_new_files', False) \
                            or config[path].get('watch_files', False)
                        if watch_this:
                            if not excludes(event.pathname):
                                log.debug("add file-watch path={0}".format(event.pathname))
                                FILE_WATCH[path].update(
                                    wm.add_watch(event.pathname, pyinotify.IN_MODIFY)
                                )
                    elif event.mask & pyinotify.IN_DELETE:
                        wd = wm.get_wd(event.pathname)
                        if wd:
                            log.debug("remove file-watch path={0}".format(event.pathname))
                            wm.del_watch(wd)
            else:
                log.info('Excluding {0} from event for {1}'.format(event.pathname, path))

    if update_watches:
        # Update existing watches and add new ones
        # TODO: make the config handle more options
        for path in config:
            excludes = lambda x: False
            if path == 'return' or path == 'checksum' or path == 'stats' \
                    or path == 'batch' or path == 'verbose' or path == 'paths' \
                    or path == 'refresh_interval':
                continue
            if isinstance(config[path], dict):
                mask = config[path].get('mask', DEFAULT_MASK)
                watch_files = config[path].get('watch_files', DEFAULT_MASK)
                if watch_files:
                    # we're going to get dup modify events if watch_files is set
                    # and we still monitor modify for the dir
                    mask -= mask & pyinotify.IN_MODIFY
                excludes = _preprocess_excludes( config[path].get('exclude') )
                if isinstance(mask, list):
                    r_mask = 0
                    for sub in mask:
                        r_mask |= _get_mask(sub)
                elif isinstance(mask, salt.ext.six.binary_type):
                    r_mask = _get_mask(mask)
                else:
                    r_mask = mask
                mask = r_mask
                rec = config[path].get('recurse', False)
                auto_add = config[path].get('auto_add', False)
                watch_files = config[path].get('watch_files', False)
            else:
                mask = DEFAULT_MASK
                rec = False
                auto_add = False
                watch_files = False

            wd = wm.get_wd(path)
            if wd:
                update = False
                if wm.watches[wd].mask != mask:
                    update = True
                if wm.watches[wd].auto_add != auto_add:
                    update = True
                if update:
                    log.debug("update watch path={p} mask={m}, auto_add={aa}".format(p=path, m=mask, aa=auto_add))
                    wm.update_watch(wd, mask=mask, rec=rec, auto_add=auto_add)
            elif os.path.exists(path):
                log.debug("add watch path={p} mask={m}, auto_add={aa}".format(p=path, m=mask, aa=auto_add))
                wm.add_watch(path, mask, rec=rec, auto_add=auto_add, exclude_filter=excludes)

            if watch_files and path not in FILE_WATCH:
                # NOTE: we use FILE_WATCH as a database of 
                # which dirwatch "owns" the file watches, such that if the
                # configs on the path change, we know what later to do
                FILE_WATCH[path] = dict()
                dt.mark('wrecurse')
                c_new, c_old = 0,0
                for wpath,wdirs,wfiles in os.walk(path):
                    if rec or wpath == path:
                        for f in wfiles:
                            wpathname = os.path.join(wpath,f)
                            if excludes(wpathname):
                                continue
                            if os.path.islink(wpathname):
                                continue
                            wd = wm.get_wd(wpathname)
                            if wd:
                                c_old += 1
                            else:
                                c_new += 1
                                FILE_WATCH[path].update(
                                    wm.add_watch(wpathname, pyinotify.IN_MODIFY)
                                )

                log.debug("recursive file-watch totals for path={path}: delta-t: {t:0.1f}; new-this-loop: {n}; "
                    "previously watched: {p}".format(path=path, t=dt.wrecurse, n=c_new, p=c_old))

        # delete any un-configured watches
        # * mark any watches that are part of a watch_files setting as OK
        # * note any watches that are configured
        # * subtract all OK file watches from that list
        # * delete what's left and finally,
        # * update the FILE_WATCH database
        dt.mark('drecurse')
        ok_file_watches = set()
        to_delete = set()
        def _in_path(ipath):
            for path in config:
                if ipath.startswith(path) and os.path.isdir(ipath):
                    return True
            return False

        for wd in wm.watches:
            ipath = wm.watches[wd].path
            if ipath in config:
                if config[ipath].get('watch_files') or config[ipath].get('watch_new_files'):
                    ok_file_watches.update( FILE_WATCH[ipath] )
            elif _in_path(ipath):
                pass
            else:
                to_delete.add(ipath)
                if ipath in FILE_WATCH:
                    del FILE_WATCH[ipath]
        to_delete -= ok_file_watches
        dc = 0
        for dpath in to_delete:
            wd = wm.get_wd(dpath)
            wm.del_watch(wd)
            dc += 1
        if dc:
            log.debug("stopped watching files/dirs: count={dc} delta_t={t:0.1f}".format(
                dc=dc, t=dt.drecurse ))

    if __salt__['config.get']('hubblestack:pulsar:maintenance', False):
        # We're in maintenance mode, throw away findings
        ret = []

    dt = dt.top
    if dt >= 0.1:
        log.debug("process sweep delta_t={t:0.1f}".format(t=dt))
    return ret


def canary(change_file=None):
    '''
    Simple module to change a file to trigger a FIM event (daily, etc)

    THE SPECIFIED FILE WILL BE CREATED AND DELETED

    Defaults to CONF_DIR/fim_canary.tmp, i.e. /etc/hubble/fim_canary.tmp
    '''
    if change_file is None:
        conf_dir = os.path.dirname(__opts__['conf_file'])
        change_file = os.path.join(conf_dir, 'fim_canary.tmp')
    __salt__['file.touch'](change_file)
    __salt__['file.remove'](change_file)


def _dict_update(dest, upd, recursive_update=True, merge_lists=False):
    '''
    Recursive version of the default dict.update

    Merges upd recursively into dest

    If recursive_update=False, will use the classic dict.update, or fall back
    on a manual merge (helpful for non-dict types like FunctionWrapper)

    If merge_lists=True, will aggregate list object types instead of replace.
    This behavior is only activated when recursive_update=True. By default
    merge_lists=False.
    '''
    if (not isinstance(dest, collections.Mapping)) \
            or (not isinstance(upd, collections.Mapping)):
        raise TypeError('Cannot update using non-dict types in dictupdate.update()')
    updkeys = list(upd.keys())
    if not set(list(dest.keys())) & set(updkeys):
        recursive_update = False
    if recursive_update:
        for key in updkeys:
            val = upd[key]
            try:
                dest_subkey = dest.get(key, None)
            except AttributeError:
                dest_subkey = None
            if isinstance(dest_subkey, collections.Mapping) \
                    and isinstance(val, collections.Mapping):
                ret = _dict_update(dest_subkey, val, merge_lists=merge_lists)
                dest[key] = ret
            elif isinstance(dest_subkey, list) \
                    and isinstance(val, list):
                if merge_lists:
                    dest[key] = dest.get(key, []) + val
                else:
                    dest[key] = upd[key]
            else:
                dest[key] = upd[key]

        return dest
    else:
        try:
            for k in upd.keys():
                dest[k] = upd[k]
        except AttributeError:
            # this mapping is not a dict
            for k in upd:
                dest[k] = upd[k]
        return dest


def top(topfile='salt://hubblestack_pulsar/top.pulsar',
        verbose=False):

    configs = get_top_data(topfile)

    configs = ['salt://hubblestack_pulsar/' + config.replace('.', '/') + '.yaml'
               for config in configs]

    return process(configs, verbose=verbose)


def get_top_data(topfile):

    topfile = __salt__['cp.cache_file'](topfile)

    try:
        with open(topfile) as handle:
            topdata = yaml.safe_load(handle)
    except Exception as e:
        raise CommandExecutionError('Could not load topfile: {0}'.format(e))

    if not isinstance(topdata, dict) or 'pulsar' not in topdata or \
            not(isinstance(topdata['pulsar'], dict)):
        raise CommandExecutionError('Pulsar topfile not formatted correctly')

    topdata = topdata['pulsar']

    ret = []

    for match, data in topdata.iteritems():
        if __salt__['match.compound'](match):
            ret.extend(data)

    return ret
