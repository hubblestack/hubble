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
import multiprocessing
import os
import re
import yaml

# Import salt libs
import salt.ext.six
import salt.loader

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
__version__ = 'v2016.10.3'
CONFIG = None
CONFIG_STALENESS = 0

import logging
log = logging.getLogger(__name__)


def __virtual__():
    if salt.utils.is_windows():
        return False, 'This module only works on Linux'
    if HAS_PYINOTIFY:
        return __virtualname__
    return False


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


def beacon(config):
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
      Recursively watch files in the directory
    auto_add:
      Automatically start watching files that are created in the watched directory
    exclude:
      Exclude directories or files from triggering events in the watched directory.
      Can use regex if regex is set to True

    If pillar/grains/minion config key `hubblestack:pulsar:maintenance` is set to
    True, then changes will be discarded.
    '''
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
            log.debug('No cached config found for pulsar, retrieving fresh from disk.')
        new_config = config
        if isinstance(config.get('paths'), list):
            for path in config['paths']:
                if 'salt://' in path:
                    log.error('Path {0} is not an absolute path. Please use a '
                              'scheduled cp.cache_file job to deliver the '
                              'config to the minion, then provide the '
                              'absolute path to the cached file on the minion '
                              'in the beacon config.'.format(path))
                    continue
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

            _append = True
            # Find the matching path in config
            path = event.path
            while path != '/':
                if path in config:
                    break
                path = os.path.dirname(path)
            # Get pathname
            try:
                pathname = event.pathname
            except NameError:
                pathname = path

            excludes = config[path].get('exclude', '')
            if excludes and isinstance(excludes, list):
                for exclude in excludes:
                    if isinstance(exclude, dict):
                        if exclude.values()[0].get('regex', False):
                            try:
                                if re.search(exclude.keys()[0], event.pathname):
                                    _append = False
                            except:
                                log.warn('Failed to compile regex: {0}'.format(exclude.keys()[0]))
                                pass
                        else:
                            exclude = exclude.keys()[0]
                    elif '*' in exclude:
                        if fnmatch.fnmatch(event.pathname, exclude):
                            _append = False
                    else:
                        if event.pathname.startswith(exclude):
                            _append = False

            if _append:
                sub = {'tag': event.path,
                       'path': event.pathname,
                       'change': event.maskname,
                       'name': event.name}

                if config.get('checksum', False) and os.path.isfile(pathname):
                    sum_type = config['checksum']
                    if not isinstance(sum_type, salt.ext.six.string_types):
                        sum_type = 'sha256'
                    sub['checksum'] = __salt__['file.get_hash'](pathname, sum_type)
                    sub['checksum_type'] = sum_type
                if config.get('stats', False):
                    sub['stats'] = __salt__['file.stats'](pathname)

                ret.append(sub)
            else:
                log.info('Excluding {0} from event for {1}'.format(event.pathname, path))

    if update_watches:
        # Get paths currently being watched
        current = set()
        for wd in wm.watches:
            current.add(wm.watches[wd].path)

        # Update existing watches and add new ones
        # TODO: make the config handle more options
        for path in config:
            if path == 'return' or path == 'checksum' or path == 'stats' \
                    or path == 'batch' or path == 'verbose' or path == 'paths' \
                    or path == 'refresh_interval':
                continue
            if isinstance(config[path], dict):
                mask = config[path].get('mask', DEFAULT_MASK)
                excludes = config[path].get('exclude', None)
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

            if path in current:
                for wd in wm.watches:
                    if path == wm.watches[wd].path:
                        update = False
                        if wm.watches[wd].mask != mask:
                            update = True
                        if wm.watches[wd].auto_add != auto_add:
                            update = True
                        if update:
                            wm.update_watch(wd, mask=mask, rec=rec, auto_add=auto_add)
            elif os.path.exists(path):
                excl = None
                if isinstance(excludes, list):
                    excl = []
                    for exclude in excludes:
                        if isinstance(exclude, dict):
                            excl.append(exclude.keys()[0])
                        else:
                            excl.append(exclude)
                    excl = pyinotify.ExcludeFilter(excl)

                wm.add_watch(path, mask, rec=rec, auto_add=auto_add, exclude_filter=excl)

        # Process watch removals
        to_delete = []
        for wd in wm.watches:
            found = False
            for path in config:
                if path in wm.watches[wd].path:
                    found = True
            if not found:
                to_delete.append(wd)
        for wd in to_delete:
            wm.del_watch(wd)

    if __salt__['config.get']('hubblestack:pulsar:maintenance', False):
        # We're in maintenance mode, throw away findings
        ret = []

    if ret and 'return' in config:
        __opts__['grains'] = __grains__
        __opts__['pillar'] = __pillar__
        __returners__ = salt.loader.returners(__opts__, __salt__)
        return_config = config['return']
        if isinstance(return_config, salt.ext.six.string_types):
            tmp = {}
            for conf in return_config.split(','):
                tmp[conf] = None
            return_config = tmp
        for returner_mod in return_config:
            returner = '{0}.returner'.format(returner_mod)
            if returner not in __returners__:
                log.error('Could not find {0} returner for pulsar beacon'.format(config['return']))
                return ret
            batch_config = config.get('batch')
            if isinstance(return_config[returner_mod], dict) and return_config[returner_mod].get('batch'):
                batch_config = True
            if batch_config:
                transformed = []
                for item in ret:
                    transformed.append({'return': item})
                if config.get('multiprocessing_return', True):
                    p = multiprocessing.Process(target=__returners__[returner], args=(transformed,))
                    p.daemon = True
                    p.start()
                else:
                    __returners__[returner](transformed)
            else:
                for item in ret:
                    if config.get('multiprocessing_return', True):
                        p = multiprocessing.Process(target=__returners__[returner], args=({'return': item},))
                        p.daemon = True
                        p.start()
                    else:
                        __returners__[returner]({'return': item})
        return []
    else:
        # Return event data
        return ret


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
                ret = update(dest_subkey, val, merge_lists=merge_lists)
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
