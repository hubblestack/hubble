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

class ConfigManager(object):
    _config = {}
    _last_update = 0

    @property
    def config(self):
        if self.stale():
            self.update()
        return self.nc_config

    @property
    def nc_config(self):
        return self.__class__._config

    @nc_config.setter
    def nc_config(self, v):
        self.__class__._config = v

    @config.setter
    def config(self, v):
        return self.nc_config.update(v)

    @property
    def last_update(self):
        return self.__class__._last_update

    @last_update.setter
    def last_update(self, v):
        self.__class__._last_update = v

    def stale(self):
        if (time.time() - self.last_update) >= self.nc_config.get('refresh_interval', 300):
            return True
        return False

    def path_config(self, path, falsifyable=False):
        config = self.nc_config
        if falsifyable and path not in config:
            return False
        c = collections.defaultdict(lambda: False)
        c.update( config.get(path, {}) )
        return c

    def _abspathify(self):
        c = self.nc_config
        for k in tuple(c):
            if k.startswith('/'):
                l = os.path.abspath(k)
                if k != l:
                    c[l] = c.pop(k)

    def update(self):
        config = self.nc_config
        to_set = __opts__.get('pulsar', {})

        # Is there a better way to tell if __opts__ updated?
        # Is it worth checking anyway? Seems only to come up in tests/
        # todo?: attempt to re-read /etc/hubble/hubble sometimes?
        counter = len( set(config).symmetric_difference( set(to_set) ) )
        if counter == 0:
            for k in config:
                if config[k] != to_set[k]:
                    counter += 1

        if isinstance(config.get('paths'), (list,tuple)):
            for path in config['paths']:
                if 'salt://' in path:
                    path = __salt__['cp.cache_file'](path)
                if os.path.isfile(path):
                    with open(path, 'r') as f:
                        to_set = _dict_update(to_set, yaml.safe_load(f),
                            recursive_update=True, merge_lists=True)
                    counter += 1
                else:
                    log.error('Path {0} does not exist or is not a file'.format(path))
        else:
            log.error('Pulsar beacon \'paths\' data improperly formatted. Should be list of paths')
        if counter>0:
            self.nc_config = to_set
            self._abspathify()
            if config.get('verbose'):
                log.debug('Pulsar config updated')
        self.last_update = time.time()

    def __init__(self, configfile=None, verbose=False):
        if configfile is not None:
            if isinstance(configfile, (list,tuple)):
                self.nc_config['paths'] = configfile
            else:
                self.nc_config['paths'] = [configfile]
        else:
            self.nc_config['paths'] = []
        config = self.config
        config['verbose'] = verbose
        self._abspathify()

class PulsarWatchManager(pyinotify.WatchManager):
    ''' Subclass of pyinotify.WatchManager for the purposes:
        * adding dict() based watch_db (for faster lookups)
        * adding file watches (to notice changes to hardlinks outside the watched locations)
        * adding various convenience functions

        pyinotify.WatchManager tracks watches internally, but only for directories
        and only in a list format. Such that many lookups take on a list-within-list
        O(n^2) complexity (eg):

        .. code-block:: python

            for path in path_list:
                wd = wm.get_wd(i) # search watch-list in an internal for loop
    '''

    def __init__(self, *a, **kw):
        # because the salt loader periodically reloads everything,
        # it becomes necessary to store the super class. Arguably, we
        # could instead use pyinotify.WatchManager.__init__(self, ...)
        # but super() lets us work with MRO later iff necessary
        self.__super = super(PulsarWatchManager, self)

        self.__super.__init__(*a, **kw)
        self.watch_db  = dict()
        self.parent_db = dict()

        self._last_config_update = 0
        self.update_config()



    @classmethod
    def _iterate_anything(cls, x, discard_none=True):
        ''' iterate any amount of list/tuple nesting
        '''
        if isinstance(x, (list,tuple,set,dict)):
            # ∀ item ∈ x: listify(item)
            for list_or_item in x:
                for i in cls._listify_anything(list_or_item):
                    if i is None and discard_none:
                        continue
                    yield i # always a scalar
        elif x is None and discard_none:
            pass
        else:
            yield x # always a scalar

    @classmethod
    def _listify_anything(cls, x, discard_none=True):
        ''' _iterate_anything, then uniquify and force a list return; because,
            pyinotify's __format_param, checks only isinstance(item,list)
        '''
        s = set( cls._iterate_anything(x, discard_none=discard_none) )
        return list(s)

    def _add_db(self, parent, **items):
	# this assumes bijection, which isn't necessarily true
	# (we hope it's true though)
        self.watch_db.update(**items)
        if parent and not items:
            raise Exception("_add_db(parent, {path: wd, path2: wd2, ...})")
        if parent in items:
            items = items.copy()
            del items[parent]
        if items:
            if parent not in self.parent_db:
                self.parent_db[parent] = set()
            self.parent_db[parent].update( items )

    def _get_wdl(self, *pathlist):
        ''' inverse pathlist and return a flat list of wd's for the paths and their child paths
            probably O( (N+M)^2 ); use sparingly
        '''
        super_list = self._listify_anything(pathlist,
            [ self.parent_db.get(x) for x in self._iterate_anything(pathlist) ])
        return self._listify_anything([ self.watch_db.get(x) for x in super_list ])

    def _get_paths(self, *wdl):
        wdl = self._listify_anything(wdl)
        return self._listify_anything([ k for k,v in salt.ext.six.iteritems(self.watch_db) if v in wdl ])

    def update_config(self):
        ''' (re)check the config files for inotify_limits:
            * inotify_limits:update - whether we should try to manage fs.inotify.max_user_watches
            * inotify_limits:highwater - the highest we should set MUW (default: 1000000)
            * inotify_limits:increment - the amount we should increase MUW when applicable
            * inotify_limits:initial   - if given, and if MUW is initially lower at startup: set MUW to this
        '''

        if not hasattr(self, 'cm'):
            self.cm = ConfigManager()
        else:
            self.cm.update()

        config = self.cm.config.get('inotify_limits', {})
        self.update_muw = config.get('update', False)
        self.update_muw_highwater = config.get('highwater', 1000000)
        self.update_muw_bump = config.get('increment', 1000)

        initial = config.get('initial', 0)
        if initial > 0:
            muw = self.max_user_watches
            if muw < initial:
                self.max_user_watches = initial

    @property
    def max_user_watches(self):
        ''' getter/setter for fs.inotify.max_user_watches
        '''
        with open('/proc/sys/fs/inotify/max_user_watches', 'r') as fh:
            l = fh.readline()
            muw = int(l.strip())
        return muw

    @max_user_watches.setter
    def max_user_watches(self,muwb):
        log.info("Setting fs.inotify.max_user_watches={0}".format(muwb))
        with open('/proc/sys/fs/inotify/max_user_watches', 'w') as fh:
            fh.write('{0}\n'.format(muwb))

    def _add_recursed_file_watch(self, path, mask=pyinotify.IN_MODIFY, **kw):
        if os.path.isdir(path):
            # this used to be if not os.path.isfile(); turns out socket files aren't isfile()s
            raise Exception("use add_watch() or watch() for directories like path={0}".format(path))
        if os.path.islink(path):
            return {}
        path = os.path.abspath(path)
        up_path = kw.pop('parent', False)
        if not up_path:
            up_path = os.path.dirname(path)
            while len(up_path) > 1 and up_path not in self.watch_db:
                up_path = os.path.dirname(up_path)
        if up_path and up_path in self.watch_db:
            res = self.add_watch(path, pyinotify.IN_MODIFY, no_db=True)
            self._add_db(up_path, **res)
            return res
        else:
            raise Exception("_add_recursed_file_watch('{0}') must be located in a watched directory".format(path))

    def watch(self, path, mask=None, **kw):
        ''' Automatically select add_watch()/update_watch() and try to do the right thing.
            Also add 'new_file' argument: add an IN_MODIFY watch for the named filepath and track it
        '''
        path     = os.path.abspath(path)
        new_file = kw.pop('new_file', False)

        if not os.path.exists(path):
            log.debug("watch({0}): NOENT (skipping)".format(path))
            return

        if mask is None:
            mask = DEFAULT_MASK

        wd = self.watch_db.get(path)
        if wd:
            update = False
            if self.watches[wd].mask != mask:
                update = True
            if self.watches[wd].auto_add != kw.get('auto_add'):
                update = True
            if update:
                kw['mask'] = mask
                kw.pop('exclude_filter',None)
                self.update_watch(wd,**kw)
                log.debug('update-watch wd={0} path={1}'.format(wd,path))
        else:
            self.add_watch(path,mask,**kw)
            log.debug('add-watch wd={0} path={1}'.format(self.watch_db.get(path), path))

        if new_file: # process() says this is a new file
            self._add_recursed_file_watch(path)

        else: # watch_files if configured to do so
            pconf = self.cm.path_config(path)
            if pconf['watch_files']:
                rec = kw.get('rec')
                excludes = kw.get('exclude_filter', lambda x: False)
                if isinstance(excludes, (list,tuple)):
                    pfft = excludes
                    excludes = lambda x: x in pfft
                if path not in self.parent_db or pconf['watch_files_obsessively']:
                    file_track = self.parent_db.get(path, {})
                    log.debug("os.walk({})".format(path))
                    pre_count = len(self.watch_db)
                    for wpath,wdirs,wfiles in os.walk(path):
                        if rec or wpath == path:
                            for f in wfiles:
                                wpathname = os.path.join(wpath,f)
                                if excludes(wpathname):
                                    continue
                                if not os.path.isfile(wpathname):
                                    continue
                                if wpathname in file_track: # checking file_track isn't strictly necessary
                                    continue                # but gives a slight speedup
                                res = self._add_recursed_file_watch( wpathname, parent=path )
                    ft_count = len(self.watch_db) - pre_count
                    if ft_count > 0:
                        log.debug('recursive file-watch totals for path={0} new-this-loop: {1}'.format(path, ft_count))


    def add_watch(self, path, mask, **kw):
        ''' Curry of pyinotify.WatchManager.add_notify
            * override - quiet = False
            * automatic absolute path
            * implicit retries
        '''
        no_db = kw.pop('no_db', False)
        path = os.path.abspath(path)
        res = {}
        kw['quiet'] = False
        retries = 5
        while retries > 0:
            retries -= 1
            try:
                _res = self.__super.add_watch(path, mask, **kw)
                if isinstance(_res, dict):
                    res.update(_res)
            except pyinotify.WatchManagerError as wme:
                self.update_config()
                if isinstance(wme.wmd, dict):
                    res.update(wme.wmd) # copy over what did work before it broke
                if self.update_muw:
                    muw = self.max_user_watches
                    muwb = muw + self.update_muw_bump
                    if muwb <= self.update_muw_highwater:
                        self.max_user_watches = muwb
                        continue
                    else:
                        log.error("during add_watch({0}): max watches reached ({1}). consider "
                            "increasing the inotify_limits:highwater mark".format(path, muw))
                        break
                else:
                    log.error("during add_watch({0}): max watches reached. "
                        "consider setting the inotify_limits:udpate".format(path))
                    break
            except Exception as e:
                log.error("exception during add_watch({0}): {1}".format(path, repr(e)))
                break

        if not no_db: # I think the English of that is funny
            self._add_db(path, **res)
        return res

    def _prune_paths_to_stop_watching(self):
        inverse_parent_db = {}
        for k,v in salt.ext.six.iteritems(self.parent_db):
            for i in v:
                inverse_parent_db[i] = k
        for dirpath in self.watch_db:
            pc = self.cm.path_config(dirpath, falsifyable=True)
            if pc is False:
                if dirpath in self.parent_db:
                    # there's no config for this dir, but it had child watches at one point
                    # probably this is just nolonger configured
                    for item in self.parent_db[dirpath]:
                        yield item
                    yield dirpath
                elif dirpath not in inverse_parent_db:
                    # this doesn't seem to be in parent_db or the reverse
                    # probably nolonger configured
                    yield dirpath
            elif not pc['watch_files'] and not pc['watch_new_files'] and dirpath in self.parent_db:
                # there's config for this dir, but it nolonger allows for child watches
                for item in self.parent_db[dirpath]:
                    yield item

    def prune(self):
        to_rm = self._listify_anything([ self.watch_db[x] for x in self._prune_paths_to_stop_watching() ])
        self.rm_watch(to_rm)

    def _rm_db(self, wd):
        plist = set( self._get_paths(wd) )
        for dirpath in plist:
            if dirpath in self.watch_db:
                del self.watch_db[dirpath]
            if dirpath in self.parent_db:
                del self.parent_db[dirpath]

        # in the interests of being really really thourough make sure none of
        # the parent_db sets contain any of the removed dirpaths
        # and then make sure there's no empty sets in the parent_db
        to_fully_delete = set()
        for d,s in salt.ext.six.iteritems(self.parent_db):
            s -= plist
            if not s:
                to_fully_delete.add(d)
        for item in to_fully_delete:
            del self.parent_db[item]

    def del_watch(self, wd):
        ''' remove a watch from the watchmanager database
        '''
        self.__super.del_watch(wd)
        self._rm_db(wd)

    def rm_watch(self, *wd, **kw):
        ''' recursively unwatch things
        '''
        wdl = self._listify_anything(wd)
        res = self.__super.rm_watch(wdl, **kw)
        self._rm_db( wdl )
        return res

def _get_notifier():
    '''
    Check the context for the notifier and construct it if not present
    '''
    if 'pulsar.notifier' not in __context__:
        __context__['pulsar.queue'] = collections.deque()
        log.info("creating new watch manager")
        wm = PulsarWatchManager()
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

    cm = ConfigManager(configfile=configfile, verbose=verbose)
    stale = cm.stale
    config = cm.config

    if config.get('verbose'):
        log.debug('Pulsar beacon called.')
        log.debug('Pulsar beacon config from pillar:\n{0}'.format(config))
    ret = []
    notifier = _get_notifier()
    wm = notifier._watch_manager
    update_watches = bool( stale )

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

                if cm.config.get('stats', False):
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
                                wm.watch(event.pathname, pyinotify.IN_MODIFY, new_file=True)

                    elif event.mask & pyinotify.IN_DELETE:
                        wm.nowatch(event.pathname)
            else:
                log.info('Excluding {0} from event for {1}'.format(event.pathname, path))

    if update_watches:
        log.debug("update watches")
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
            else:
                mask = DEFAULT_MASK
                rec = False
                auto_add = False

            wm.watch(path, mask, rec=rec, auto_add=auto_add, exclude_filter=excludes)
        wm.prune()

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
