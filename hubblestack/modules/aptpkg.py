# -*- coding: utf-8 -*-
'''
Support for APT (Advanced Packaging Tool)

.. important::
    If you feel that Salt should be using this module to manage packages on a
    minion, and it is using a different module (or gives an error similar to
    *'pkg.install' is not available*), see :ref:`here
    <module-provider-override>`.

    For repository management, the ``python-apt`` package must be installed.
'''
from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
import copy
import os
import re
import logging
import time

import hubblestack.utils.data
import hubblestack.utils.pkg
import hubblestack.utils.systemd
import hubblestack.utils.environment
from hubblestack.exceptions import (
    CommandExecutionError
)

log = logging.getLogger(__name__)

# pylint: disable=import-error
try:
    import apt.cache
    import apt.debfile
    from aptsources import sourceslist
    HAS_APT = True
except ImportError:
    HAS_APT = False

try:
    import apt_pkg
    HAS_APTPKG = True
except ImportError:
    HAS_APTPKG = False

try:
    import softwareproperties.ppa
    HAS_SOFTWAREPROPERTIES = True
except ImportError:
    HAS_SOFTWAREPROPERTIES = False
# pylint: enable=import-error

APT_LISTS_PATH = "/var/lib/apt/lists"

# Source format for urllib fallback on PPA handling
DPKG_ENV_VARS = {
    'APT_LISTBUGS_FRONTEND': 'none',
    'APT_LISTCHANGES_FRONTEND': 'none',
    'DEBIAN_FRONTEND': 'noninteractive',
    'UCF_FORCE_CONFFOLD': '1',
}

# Define the module's virtual name
__virtualname__ = 'pkg'


def __virtual__():
    '''
    Confirm this module is on a Debian-based system
    '''
    # If your minion is running an OS which is Debian-based but does not have
    # an "os_family" grain of Debian, then the proper fix is NOT to check for
    # the minion's "os_family" grain here in the __virtual__. The correct fix
    # is to add the value from the minion's "os" grain to the _OS_FAMILY_MAP
    # dict in salt/grains/core.py, so that we assign the correct "os_family"
    # grain to the minion.
    if __grains__.get('os_family') == 'Debian':
        return __virtualname__
    return False, 'The pkg module could not be loaded: unsupported OS family'


def __init__(opts):
    '''
    For Debian and derivative systems, set up
    a few env variables to keep apt happy and
    non-interactive.
    '''
    if __virtual__() == __virtualname__:
        # Export these puppies so they persist
        os.environ.update(DPKG_ENV_VARS)

def list_pkgs(versions_as_list=False,
              removed=False,
              purge_desired=False,
              **kwargs):  # pylint: disable=W0613
    '''
    List the packages currently installed in a dict::

        {'<package_name>': '<version>'}

    removed
        If ``True``, then only packages which have been removed (but not
        purged) will be returned.

    purge_desired
        If ``True``, then only packages which have been marked to be purged,
        but can't be purged due to their status as dependencies for other
        installed packages, will be returned. Note that these packages will
        appear in installed

        .. versionchanged:: 2014.1.1

            Packages in this state now correctly show up in the output of this
            function.
    '''
    versions_as_list = hubblestack.utils.data.is_true(versions_as_list)
    removed = hubblestack.utils.data.is_true(removed)
    purge_desired = hubblestack.utils.data.is_true(purge_desired)

    if 'pkg.list_pkgs' in __context__:
        if removed:
            ret = copy.deepcopy(__context__['pkg.list_pkgs']['removed'])
        else:
            ret = copy.deepcopy(__context__['pkg.list_pkgs']['purge_desired'])
            if not purge_desired:
                ret.update(__context__['pkg.list_pkgs']['installed'])
        if not versions_as_list:
            __mods__['pkg_resource.stringify'](ret)
        return ret

    ret = {'installed': {}, 'removed': {}, 'purge_desired': {}}
    cmd = ['dpkg-query', '--showformat',
           '${Status} ${Package} ${Version} ${Architecture}\n', '-W']

    out = __mods__['cmd.run_stdout'](
            cmd,
            output_loglevel='trace',
            python_shell=False)
    # Typical lines of output:
    # install ok installed zsh 4.3.17-1ubuntu1 amd64
    # deinstall ok config-files mc 3:4.8.1-2ubuntu1 amd64
    for line in out.splitlines():
        cols = line.split()
        try:
            linetype, status, name, version_num, arch = \
                [cols[x] for x in (0, 2, 3, 4, 5)]
        except (ValueError, IndexError):
            continue
        if __grains__.get('cpuarch', '') == 'x86_64':
            osarch = __grains__.get('osarch', '')
            if arch != 'all' and osarch == 'amd64' and osarch != arch:
                name += ':{0}'.format(arch)
        if len(cols):
            if ('install' in linetype or 'hold' in linetype) and \
                    'installed' in status:
                __mods__['pkg_resource.add_pkg'](ret['installed'],
                                                 name,
                                                 version_num)
            elif 'deinstall' in linetype:
                __mods__['pkg_resource.add_pkg'](ret['removed'],
                                                 name,
                                                 version_num)
            elif 'purge' in linetype and status == 'installed':
                __mods__['pkg_resource.add_pkg'](ret['purge_desired'],
                                                 name,
                                                 version_num)

    for pkglist_type in ('installed', 'removed', 'purge_desired'):
        __mods__['pkg_resource.sort_pkglist'](ret[pkglist_type])

    __context__['pkg.list_pkgs'] = copy.deepcopy(ret)

    if removed:
        ret = ret['removed']
    else:
        ret = copy.deepcopy(__context__['pkg.list_pkgs']['purge_desired'])
        if not purge_desired:
            ret.update(__context__['pkg.list_pkgs']['installed'])
    if not versions_as_list:
        __mods__['pkg_resource.stringify'](ret)
    return ret

def version(*names, **kwargs):
    '''
    Returns a string representing the package version or an empty string if not
    installed. If more than one package name is specified, a dict of
    name/version pairs is returned.
    '''
    return __mods__['pkg_resource.version'](*names, **kwargs)

def version_cmp(pkg1, pkg2, ignore_epoch=False):
    '''
    Do a cmp-style comparison on two packages. Return -1 if pkg1 < pkg2, 0 if
    pkg1 == pkg2, and 1 if pkg1 > pkg2. Return None if there was a problem
    making the comparison.

    ignore_epoch : False
        Set to ``True`` to ignore the epoch when comparing versions

        .. versionadded:: 2015.8.10,2016.3.2
    '''
    normalize = lambda x: str(x).split(':', 1)[-1] \
                if ignore_epoch else str(x)
    # both apt_pkg.version_compare and _cmd_quote need string arguments.
    pkg1 = normalize(pkg1)
    pkg2 = normalize(pkg2)

    # if we have apt_pkg, this will be quickier this way
    # and also do not rely on shell.
    if HAS_APTPKG:
        try:
            # the apt_pkg module needs to be manually initialized
            apt_pkg.init_system()

            # if there is a difference in versions, apt_pkg.version_compare will
            # return an int representing the difference in minor versions, or
            # 1/-1 if the difference is smaller than minor versions. normalize
            # to -1, 0 or 1.
            try:
                ret = apt_pkg.version_compare(pkg1, pkg2)
            except TypeError:
                ret = apt_pkg.version_compare(str(pkg1), str(pkg2))
            return 1 if ret > 0 else -1 if ret < 0 else 0
        except Exception:
            # Try to use shell version in case of errors w/python bindings
            pass
    try:
        for oper, ret in (('lt', -1), ('eq', 0), ('gt', 1)):
            cmd = ['dpkg', '--compare-versions', pkg1, oper, pkg2]
            retcode = __mods__['cmd.retcode'](cmd,
                                              output_loglevel='trace',
                                              python_shell=False,
                                              ignore_retcode=True)
            if retcode == 0:
                return ret
    except Exception as exc:
        log.error(exc)
    return None

def refresh_db(cache_valid_time=0, failhard=False):
    '''
    Updates the APT database to latest packages based upon repositories

    Returns a dict, with the keys being package databases and the values being
    the result of the update attempt. Values can be one of the following:

    - ``True``: Database updated successfully
    - ``False``: Problem updating database
    - ``None``: Database already up-to-date

    cache_valid_time

        .. versionadded:: 2016.11.0

        Skip refreshing the package database if refresh has already occurred within
        <value> seconds

    failhard

        If False, return results of Err lines as ``False`` for the package database that
        encountered the error.
        If True, raise an error with a list of the package databases that encountered
        errors.
    '''
    # Remove rtag file to keep multiple refreshes from happening in pkg states
    hubblestack.utils.pkg.clear_rtag(__opts__)
    failhard = hubblestack.utils.data.is_true(failhard)
    ret = {}
    error_repos = list()

    if cache_valid_time:
        try:
            latest_update = os.stat(APT_LISTS_PATH).st_mtime
            now = time.time()
            log.debug("now: %s, last update time: %s, expire after: %s seconds", now, latest_update, cache_valid_time)
            if latest_update + cache_valid_time > now:
                return ret
        except TypeError as exp:
            log.warning("expected integer for cache_valid_time parameter, failed with: %s", exp)
        except IOError as exp:
            log.warning("could not stat cache directory due to: %s", exp)

    call = _call_apt(['apt-get', '-q', 'update'], scope=False)
    if call['retcode'] != 0:
        comment = ''
        if 'stderr' in call:
            comment += call['stderr']

        raise CommandExecutionError(comment)
    else:
        out = call['stdout']

    for line in out.splitlines():
        cols = line.split()
        if not cols:
            continue
        ident = ' '.join(cols[1:])
        if 'Get' in cols[0]:
            # Strip filesize from end of line
            ident = re.sub(r' \[.+B\]$', '', ident)
            ret[ident] = True
        elif 'Ign' in cols[0]:
            ret[ident] = False
        elif 'Hit' in cols[0]:
            ret[ident] = None
        elif 'Err' in cols[0]:
            ret[ident] = False
            error_repos.append(ident)

    if failhard and error_repos:
        raise CommandExecutionError('Error getting repos: {0}'.format(', '.join(error_repos)))

    return ret

def _call_apt(args, scope=True, **kwargs):
    '''
    Call apt* utilities.
    '''
    cmd = []
    if scope and hubblestack.utils.systemd.has_scope(__context__) and __mods__['config.get']('systemd.scope', True):
        cmd.extend(['systemd-run', '--scope'])
    cmd.extend(args)

    params = {'output_loglevel': 'trace',
              'python_shell': False,
              'env': hubblestack.utils.environment.get_module_environment(globals())}
    params.update(kwargs)

    return __mods__['cmd.run_all'](cmd, **params)
