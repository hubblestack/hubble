# -*- coding: utf-8 -*-
"""
Watch files and translate the changes into salt events

:depends:   - pyinotify Python module >= 0.9.5

:Caution:   Using generic mask options like open, access, ignored, and
            closed_nowrite with reactors can easily cause the reactor
            to loop on itself. To mitigate this behavior, consider
            setting the `disable_during_state_run` flag to `True` in
            the beacon configuration.

"""
# Import Python libs

import types
import base64
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
    DEFAULT_MASK = pyinotify.IN_CREATE | pyinotify.IN_DELETE | pyinotify.IN_DELETE_SELF | pyinotify.IN_MODIFY
    RM_WATCH_MASK = pyinotify.IN_DELETE | pyinotify.IN_DELETE_SELF | pyinotify.IN_IGNORED
    MASKS = {}
    for var in dir(pyinotify):
        if var.startswith('IN_'):
            key = var[3:].lower()
            MASKS[key] = getattr(pyinotify, var)
except ImportError:
    HAS_PYINOTIFY = False
    DEFAULT_MASK = None
    class pyinotify:
        WatchManager = object

__virtualname__ = 'pulsar'
SPAM_TIME = 0 # track spammy status message times
TOP = None
TOP_STALENESS = 0

import logging
log = logging.getLogger(__name__)

from hubblestack.status import HubbleStatus
hubble_status = HubbleStatus(__name__, 'top', 'process')

def __virtual__():
    if salt.utils.platform.is_windows():
        return False, 'This module only works on Linux'
    return True

def _get_mask(mask):
    """
    Return the int that represents the mask
    """
    return MASKS.get(mask, 0)


def _enqueue(revent):
    """
    Enqueue the event
    """
    __context__['pulsar.queue'].append(revent)

def _maskname_filter(name):
    """ deleting a directly watched file produces IN_DELETE_SELF (not
        IN_DELETE) and also kicks up a an IN_IGNORED (whether you mask for it
        or not) to indicate the file is nolonger watched.

        We avoid returning IN_IGNORED if we can... but IN_DELETE_SELF is
        corrected to IN_DELETE
    """
    if name == 'IN_DELETE_SELF':
        return 'IN_DELETE'
    return name

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

    def freshness(self, freshness_limit=2):
        t = time.time()
        return (t - self.last_update <= freshness_limit)

    def stale(self):
        if (time.time() - self.last_update) >= self.nc_config.get('refresh_interval', 300):
            return True
        return False

    def format_path(self, path):
        path  = os.path.abspath(path)
        fname = os.path.basename(path)
        cpath = self.path_of_config(path)
        dname = path if os.path.isdir(path) else os.path.dirname(path)
        return cpath, path, dname, fname

    def path_config(self, path, falsifyable=False):
        config = self.nc_config
        if falsifyable and path not in config:
            return False
        c = collections.defaultdict(lambda: False)
        c.update( config.get(path, {}) )
        return c

    def path_of_config(self, path):
        ncc = self.nc_config
        while len(path)>1 and path not in ncc:
            path = os.path.dirname(path)
        return path

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

        if isinstance(config.get('paths'), (list,tuple)):
            for path in config['paths']:
                if 'salt://' in path:
                    path = __salt__['cp.cache_file'](path)
                if path and os.path.isfile(path):
                    with open(path, 'r') as f:
                        to_set = _dict_update(to_set, yaml.safe_load(f),
                            recursive_update=True, merge_lists=True)
                else:
                    log.error('Path {0} does not exist or is not a file'.format(path))
        else:
            log.error('Pulsar beacon \'paths\' data improperly formatted. Should be list of paths')

        to_set['paths'] = config.get('paths')
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
        elif 'paths' not in self.nc_config:
            self.nc_config['paths'] = []
        config = self.config
        config['verbose'] = verbose
        self._abspathify()

class PulsarWatchManager(pyinotify.WatchManager):
    """ Subclass of pyinotify.WatchManager for the purposes:
        * adding dict() based watch_db (for faster lookups)
        * adding file watches (to notice changes to hardlinks outside the watched locations)
        * adding various convenience functions

        pyinotify.WatchManager tracks watches internally, but only for directories
        and only in a list format. Such that many lookups take on a list-within-list
        O(n^2) complexity (eg):

        .. code-block:: python

            for path in path_list:
                wd = wm.get_wd(i) # search watch-list in an internal for loop
    """

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
        """ iterate any amount of list/tuple nesting
        """
        if isinstance(x, (types.GeneratorType,list,tuple,set,dict)):
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
        """ _iterate_anything, then uniquify and force a list return; because,
            pyinotify's __format_param, checks only isinstance(item,list)
        """
        s = set( cls._iterate_anything(x, discard_none=discard_none) )
        return list(s)

    def _add_db(self, parent, items):
        if parent and not items:
            return
        todo = {}
        for i in items:
            if items[i] > 0:
                todo[i] = items[i]
        self.watch_db.update(todo)
        if parent in todo:
            del todo[parent]
        if todo:
            if parent not in self.parent_db:
                self.parent_db[parent] = set()
            self.parent_db[parent].update(todo)

    def _get_wdl(self, *pathlist):
        """ inverse pathlist and return a flat list of wd's for the paths and their child paths
            probably O( (N+M)^2 ); use sparingly
        """
        super_list = self._listify_anything(pathlist,
            [ x if isinstance(x,int) else self.parent_db.get(x) for x in self._iterate_anything(pathlist) ])
        return self._listify_anything([ x if isinstance(x,int) else self.watch_db.get(x) for x in super_list ])

    def _get_paths(self, *wdl):
        wdl = self._listify_anything(wdl)
        return self._listify_anything([ k for k,v in salt.ext.six.iteritems(self.watch_db) if v in wdl ])

    def update_config(self):
        """ (re)check the config files for inotify_limits:
            * inotify_limits:update - whether we should try to manage fs.inotify.max_user_watches
            * inotify_limits:highwater - the highest we should set MUW (default: 1000000)
            * inotify_limits:increment - the amount we should increase MUW when applicable
            * inotify_limits:initial   - if given, and if MUW is initially lower at startup: set MUW to this
        """

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
        """ getter/setter for fs.inotify.max_user_watches
        """
        with open('/proc/sys/fs/inotify/max_user_watches', 'r') as fh:
            l = fh.readline()
            muw = int(l.strip())
        return muw

    @max_user_watches.setter
    def max_user_watches(self,muwb):
        log.splunk("Setting fs.inotify.max_user_watches={0}".format(muwb))
        try:
            with open('/proc/sys/fs/inotify/max_user_watches', 'w') as fh:
                fh.write('{0}\n'.format(muwb))
        except IOError as e:
            log.error("Error updating sys.fs.inotify.max_user_watches: %s", e)

    def _add_recursed_file_watch(self, path, mask=None, **kw):
        if mask is None:
            # don't simply set this as default above
            # (it seems to get messed up by the namespace reload during grains refresh)
            mask = pyinotify.IN_MODIFY
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
            # we already did many of the lookups add_watch would do
            # so we say no_db=True and manually add the (up_path,**res)
            res = self.add_watch(path, mask, no_db=True)
            self._add_db(up_path, res)
            return res
        else:
            raise Exception("_add_recursed_file_watch('{0}') must be located in a watched directory".format(path))

    def watch(self, path, mask=None, **kw):
        """ Automatically select add_watch()/update_watch() and try to do the right thing.
            Also add 'new_file' argument: add an IN_MODIFY watch for the named filepath and track it
        """
        path     = os.path.abspath(path)
        new_file = kw.pop('new_file', False)

        if not os.path.exists(path):
            log.debug("watch({0}): NOENT (skipping)".format(path))
            return

        if mask is None:
            mask = DEFAULT_MASK

        pconf = self.cm.path_config(path)
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
                log.debug('update-watch wd={0} path={1} watch_files={2} recurse={3}'.format(
                    wd, path, pconf['watch_files'], pconf['recurse']))
        else:
            if 'recurse' in kw:
                kw['rec'] = kw.pop('recurse')
            kw['rec'] = kw.get('rec')
            if kw['rec'] is None:
                kw['rec'] = pconf['recurse']
            self.add_watch(path, mask, **kw)
            log.debug('add-watch wd={0} path={1} watch_files={2} recurse={3} mask={4}'.format(
                self.watch_db.get(path), path, pconf['watch_files'], kw['rec'], mask))

        if new_file: # process() says this is a new file
            self._add_recursed_file_watch(path)

        else: # watch_files if configured to do so
            if pconf['watch_files']:
                rec = kw.get('rec')
                excludes = kw.get('exclude_filter', lambda x: False)
                if isinstance(excludes, (list,tuple)):
                    pfft = excludes
                    excludes = lambda x: x in pfft
                file_track = self.parent_db.get(path, {})
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
                            self._add_recursed_file_watch( wpathname, parent=path )
                ft_count = len(self.watch_db) - pre_count
                if ft_count > 0:
                    log.debug('recursive file-watch totals for path={0} new-this-loop: {1}'.format(path, ft_count))


    def add_watch(self, path, mask, **kw):
        """ Curry of pyinotify.WatchManager.add_notify
            * override - quiet = False
            * automatic absolute path
            * implicit retries
        """
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
                    break
                else:
                    raise Exception("pyinotify.WatchManager.add_watch() failed to return a dict")
            except pyinotify.WatchManagerError as wme:
                log.error(wme)
                if 'permission denied' in str(wme).lower():
                    continue # assume it's just this one file/dir
                else:
                    # when we can't add more watches becuase of
                    #   sysctl -q fs.inotify.max_user_watches
                    # the error is (roughly), "Errno=No space left on device (ENOSPC)".
                    # Is that always the case? It's hard to say for sure.
                    self.update_config() # make sure we have the latest settings
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

        if not no_db: # (heh)
            self._add_db(path, res)
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
            elif dirpath in self.parent_db:
                for item in self.parent_db[dirpath]:
                    if os.path.isdir(item):
                        if not pc['recurse']:
                            # there's config for this dir, but it nolonger recurses
                            yield item
                    elif not pc['watch_files'] and not pc['watch_new_files']:
                        # there's config for this dir, but it nolonger watches files
                        yield item

    def prune(self):
        def _wd(l):
            for item in l:
                yield self.watch_db[item]
        to_stop = self._prune_paths_to_stop_watching()
        to_rm = self._listify_anything( _wd(to_stop) )
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
        """ remove a watch from the watchmanager database
        """
        if not isinstance(wd, int):
            wd = self._get_wdl(wd)[0]
        self.__super.del_watch(wd)
        self._rm_db(wd)

    def rm_watch(self, *wd, **kw):
        """ recursively unwatch things
        """
        wdl = self._get_wdl(wd)
        res = self.__super.rm_watch(wdl, **kw)
        self._rm_db(wdl)
        return res

def _get_notifier():
    """
    Check the context for the notifier and construct it if not present
    """
    if 'pulsar.notifier' not in __context__:
        __context__['pulsar.queue'] = collections.deque()
        log.info("creating new watch manager")
        wm = PulsarWatchManager()
        __context__['pulsar.notifier'] = pyinotify.Notifier(wm, _enqueue)
    return __context__['pulsar.notifier']

def _preprocess_excludes(excludes):
    """
    Wrap excludes in simple decision curry functions.
    """

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
            first_val = list(e.values())[0]
            first_key = list(e.keys())[0]
            if first_val.get('regex'):
                r = first_key
                try:
                    c = re.compile(r)
                    the_list.append(re_wrapper(c))
                except Exception as e:
                    log.warning('Failed to compile regex "%s": %s', r, e)
                continue
            else:
                e = first_key
        if '*' in e:
            the_list.append(fn_wrapper(e))
        else:
            the_list.append(str_wrapper(e))

    # finally, wrap the whole decision set in a decision wrapper
    def _final(val):
        for i in the_list:
            if i(val):
                return True
        return False
    return _final

class delta_t(object):
    def __init__(self):
        self.marks = {}
        self.fins = {}
        self.mark('top')

    def __repr__(self):
        return "delta_t({0})".format(self)

    def __str__(self):
        ret = ["delta_t={0:0.2f}".format(self.get())]
        for i in sorted(self.marks):
            if i in ('top',):
                continue
            ret.append("{0}={1:0.2f}".format(i, self.get(i)))
        return '; '.join(ret)

    def fin(self,name=None):
        if name is None:
            name = self.last_mark
        if name == 'top':
            return # top doesn't finish
        self.fins[name] = time.time()

    def get(self,name=None):
        if name is None:
            name = 'top'
        begin = self.marks[name]
        end   = self.fins.get(name, time.time())
        return end - begin

    def mark(self,name):
        self.last_mark = name
        self.marks[name] = time.time()

@hubble_status.watch
def process(configfile='salt://hubblestack_pulsar/hubblestack_pulsar_config.yaml',
            verbose=False):
    """
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
        contents_size: 20480
        checksum_size: 104857600

    Note that if `batch: True`, the configured returner must support receiving
    a list of events, rather than single one-off events.

    The mask list can contain the following events (the default mask is create,
    delete, and modify):

    * access            - File accessed
    * attrib            - File metadata changed
    * close_nowrite     - Unwritable file closed
    * close_write       - Writable file closed
    * create      [def] - File created in watched directory
    * delete      [def] - File deleted from watched directory
    * delete_self       - Watched file or directory deleted
    * modify      [def] - File modified
    * moved_from        - File moved out of watched directory
    * moved_to          - File moved into watched directory
    * move_self         - Watched file moved
    * open              - File opened

    The mask can also contain the following options (none enabled by default):

    * dont_follow       - Don't dereference symbolic links
    * excl_unlink       - Omit events for children after they have been unlinked
    * oneshot           - Remove watch after one event
    * onlydir           - Operate only if name is directory

    All the below options regarding further recursion and file watches default
    to False.

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
    contents:
      Retrieve the contents of changed files based on checksums (which must be enabled)
      When enabled, the options contents_size (default 20480) is also used to
      decide, "Don't fetch contents for any file over contents_size or where
      the checksum is unchanged."

    If pillar/grains/minion config key `hubblestack:pulsar:maintenance` is set to
    True, then changes will be discarded.
    """

    dt = delta_t()
    dt.mark('read_config')

    if not HAS_PYINOTIFY:
        log.debug('Not running beacon pulsar. No python-inotify installed.')
        return []

    cm = ConfigManager(configfile=configfile, verbose=verbose)
    config = cm.config

    if config.get('verbose'):
        log.debug('Pulsar beacon called.')
        log.debug('Pulsar beacon config from pillar:\n{0}'.format(config))

    ret = []
    notifier = _get_notifier()
    wm = notifier._watch_manager
    update_watches = cm.freshness(2)
    initial_count = len(wm.watch_db)

    recent = set()

    dt.fin()

    # Read in existing events
    if notifier.check_events(1):
        dt.mark('check_events')
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

            log.debug("queue {0}".format(event)) # shows mask/name/pathname/wd and other things
            k = "{0.pathname} {0.maskname}".format(event)
            if k in recent:
                log.debug("skipping event")
                continue
            recent.add(k)

            pathname = event.pathname
            cpath, abspath, dirname, basename = cm.format_path(pathname)
            # cpath              : the path under which the config is specified
            # abspath            : os.path.abspath() reformatted path
            # dirname            : the directory of the pathname, or the pathname if
            #                    : it's a directory
            # basename           : the os.path.basename() of the path
            # wpath = event.path : the path of the watch that triggered (not actually populated
            #                    : in wpath)

            excludes = _preprocess_excludes( config[cpath].get('exclude') )
            _append = not excludes(pathname)

            if _append:
                config_path = config['paths'][0]
                pulsar_config = config_path[config_path.rfind('/') + 1:len(config_path)]
                sub = { 'change': _maskname_filter(event.maskname),
                        'path': abspath,  # goes to object_path in splunk
                        'tag':  dirname,  # goes to file_path in splunk
                        'name': basename, # goes to file_name in splunk
                        'pulsar_config': pulsar_config}

                if config.get('checksum', False) and os.path.isfile(pathname):
                    if 'pulsar_checksums' not in __context__:
                        __context__['pulsar_checksums'] = {}
                    # Don't checksum any file over 100MB
                    if os.path.getsize(pathname) < config.get('checksum_size', 104857600):
                        sum_type = config['checksum']
                        if not isinstance(sum_type, salt.ext.six.string_types):
                            sum_type = 'sha256'
                        old_checksum = __context__['pulsar_checksums'].get(pathname)
                        new_checksum = __salt__['file.get_hash'](pathname, sum_type)
                        __context__['pulsar_checksums'][pathname] = new_checksum
                        sub['checksum'] = __context__['pulsar_checksums'][pathname]
                        sub['checksum_type'] = sum_type

                        # File contents? Don't fetch contents for any file over
                        # 20KB or where the checksum is unchanged
                        if (pathname in config[cpath].get('contents', []) or
                                os.path.dirname(pathname) in config[cpath].get('contents', [])) \
                                and os.path.getsize(pathname) < config.get('contents_size', 20480) \
                                and old_checksum != new_checksum:
                            try:
                                with open(pathname, 'r') as f:
                                    sub['contents'] = base64.b64encode(f.read())
                            except Exception as e:
                                log.debug('Could not get file contents for {0}: {1}'
                                          .format(pathname, e))

                if cm.config.get('stats', False):
                    if os.path.exists(pathname):
                        sub['stats'] = __salt__['file.stats'](pathname)
                    else:
                        sub['stats'] = {}
                    if os.path.isfile(pathname):
                        sub['size'] = os.path.getsize(pathname)

                if event.mask != pyinotify.IN_IGNORED:
                    ret.append(sub)

                if not event.mask & pyinotify.IN_ISDIR:
                    if event.mask & pyinotify.IN_CREATE:
                        watch_this = config[cpath].get('watch_new_files', False) \
                            or config[cpath].get('watch_files', False)
                        if watch_this:
                            if not excludes(pathname):
                                log.debug("add file-watch path={0} mask={1}".format(pathname,
                                    pyinotify.IN_MODIFY))
                                wm.watch(pathname, pyinotify.IN_MODIFY, new_file=True)
                    elif event.mask & RM_WATCH_MASK:
                        wm.rm_watch(pathname)
            else:
                log.debug('Excluding {0} from event for {1}'.format(pathname, cpath))
        dt.fin()

    if update_watches:
        dt.mark('update_watches')
        log.debug("update watches")
        # Update existing watches and add new ones
        for path in config:
            excludes = lambda x: False
            if path in ['return', 'checksum', 'stats', 'batch', 'verbose',
                        'paths', 'refresh_interval', 'contents_size',
                        'checksum_size']:
                continue
            if isinstance(config[path], dict):
                mask = config[path].get('mask', DEFAULT_MASK)
                watch_files = config[path].get('watch_files', False)
                if watch_files:
                    # we're going to get dup modify events if watch_files is set
                    # and we still monitor modify for the dir
                    mask_and_modify = mask & pyinotify.IN_MODIFY
                    if mask_and_modify:
                        log.debug("mask={0} -= mask & pyinotify.IN_MODIFY={1}" \
                            " ==> {2}".format(
                                mask,
                                mask_and_modify,
                                mask-mask_and_modify))
                        mask -= mask_and_modify
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

            if os.path.isfile(path) and not wm.get_wd(path):
                # We were not previously watching this file generate a fake
                # IN_CREATE to announce this fact.  We'd like to only generate
                # CREATE events when files are created, but we can't actually
                # watch files that don't exist yet (not with inotify anyway).
                # The kernel would rather be watching directories anyway.
                #
                # You might worry we'll get lots of spurious IN_CREATEs when
                # the database is cleared or at startup or whatever.  We
                # actually watch everyhthing from config at startup anyway; so
                # we avoid these fake IN_CREATE events at startup. They only
                # happen when we add a watch during update, which means the
                # file really is new since the last time we thought about it
                # (aka the last time we ran the process() function).
                _, abspath, dirname, basename = cm.format_path(path)
                try:
                    config_path = config['paths'][0]
                    pulsar_config = config_path[config_path.rfind('/') + 1:len(config_path)]
                except IndexError:
                    pulsar_config = 'unknown'
                fake_sub = { 'change': 'IN_CREATE',
                        'path': abspath,  # goes to object_path in splunk
                        'tag':  dirname,  # goes to file_path in splunk
                        'name': basename, # goes to file_name in splunk
                        'pulsar_config': pulsar_config}
                ret.append(fake_sub)

            wm.watch(path, mask, rec=rec, auto_add=auto_add, exclude_filter=excludes)

        dt.fin()
        dt.mark('prune_watches')
        wm.prune()
        dt.fin()

    if __salt__['config.get']('hubblestack:pulsar:maintenance', False):
        # We're in maintenance mode, throw away findings
        ret = []

    global SPAM_TIME
    now_t = time.time()
    spam_dt = now_t - SPAM_TIME
    current_count = len(wm.watch_db)
    delta_c = current_count - initial_count

    if dt.get() >= 0.1 or abs(delta_c)>0 or spam_dt >= 60:
        SPAM_TIME = now_t
        log.info("process() sweep {0}; watch count: {1} (delta: {2})".format(dt, current_count, delta_c))
        if 'DUMP_WATCH_DB' in os.environ:
            import json
            f = os.path.basename(os.environ['DUMP_WATCH_DB'])
            if f.lower() in ('1', 'true', 'yes'):
                f = 'pulsar-watch.db'
            f = '/tmp/{}'.format(f)
            with open(f, 'w') as fh:
                json.dump(wm.watch_db, fh)
            log.debug("wrote watch_db to {}".format(f))

    return ret


def canary(change_file=None):
    """
    Simple module to change a file to trigger a FIM event (daily, etc)

    THE SPECIFIED FILE WILL BE CREATED AND DELETED

    Defaults to CONF_DIR/fim_canary.tmp, i.e. /etc/hubble/fim_canary.tmp
    """
    if change_file is None:
        conf_dir = os.path.dirname(__opts__['conf_file'])
        change_file = os.path.join(conf_dir, 'fim_canary.tmp')
    __salt__['file.touch'](change_file)
    __salt__['file.remove'](change_file)


def _dict_update(dest, upd, recursive_update=True, merge_lists=False):
    """
    Recursive version of the default dict.update

    Merges upd recursively into dest

    If recursive_update=False, will use the classic dict.update, or fall back
    on a manual merge (helpful for non-dict types like FunctionWrapper)

    If merge_lists=True, will aggregate list object types instead of replace.
    This behavior is only activated when recursive_update=True. By default
    merge_lists=False.
    """
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
                    # NOTE: this is probably quite slow, but prevents a
                    # horrible memory leak ...
                    target = dest.get(key, [])
                    target += [ v for v in val if v not in target ]
                    dest[key] = target
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
    """
    Execute pulsar using a top.pulsar file to decide which configs to use for
    this host.

    The topfile should be formatted like this:

    .. code-block:: yaml

        pulsar:
          '<salt compound match identifying host(s)>':
            - list.of.paths
            - using.dots.as.directory.separators

    Paths in the topfile should be relative to `salt://hubblestack_pulsar`, and
    the .yaml should not be included.
    """
    configs = get_top_data(topfile)

    configs = ['salt://hubblestack_pulsar/' + config.replace('.', '/') + '.yaml'
               for config in configs]

    return process(configs, verbose=verbose)


def get_top_data(topfile):
    """
    Cache the topfile and process the list of configs this host should use.
    """
    # Get topdata from filesystem if we don't have them already
    global TOP
    global TOP_STALENESS
    if TOP and TOP_STALENESS < 60:
        TOP_STALENESS += 1
        topdata = TOP
    else:
        log.debug('Missing/stale cached topdata found for pulsar, retrieving fresh from fileserver.')
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
        TOP = topdata
        TOP_STALENESS = 0

    ret = []

    for match, data in topdata.items():
        if __salt__['match.compound'](match):
            ret.extend(data)

    return ret
