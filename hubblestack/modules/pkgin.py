# -*- coding: utf-8 -*-
'''
Package support for pkgin based systems, inspired from freebsdpkg module

.. important::
    If you feel that Salt should be using this module to manage packages on a
    minion, and it is using a different module (or gives an error similar to
    *'pkg.install' is not available*), see :ref:`here
    <module-provider-override>`.
'''

# Import python libs
import copy
import logging
import os
import re

# Import salt libs
import hubblestack.utils.data
import hubblestack.utils.path
import hubblestack.utils.pkg
from hubblestack.utils.decorators.memoize import memoize
from hubblestack.exceptions import CommandExecutionError

log = logging.getLogger(__name__)

# Define the module's virtual name
__virtualname__ = 'pkg'

def list_pkgs(versions_as_list=False, **kwargs):
    '''
    .. versionchanged: 2016.3.0

    List the packages currently installed as a dict::

        {'<package_name>': '<version>'}
    '''
    versions_as_list = hubblestack.utils.data.is_true(versions_as_list)
    # not yet implemented or not applicable
    if any([hubblestack.utils.data.is_true(kwargs.get(x))
            for x in ('removed', 'purge_desired')]):
        return {}

    if 'pkg.list_pkgs' in __context__:
        if versions_as_list:
            return __context__['pkg.list_pkgs']
        else:
            ret = copy.deepcopy(__context__['pkg.list_pkgs'])
            __mods__['pkg_resource.stringify'](ret)
            return ret

    pkgin = _check_pkgin()
    ret = {}

    out = __mods__['cmd.run'](
        [pkgin, 'ls'] if pkgin else ['pkg_info'],
        output_loglevel='trace')

    for line in out.splitlines():
        try:
            # Some versions of pkgin check isatty unfortunately
            # this results in cases where a ' ' or ';' can be used
            pkg, ver = re.split('[; ]', line, 1)[0].rsplit('-', 1)
        except ValueError:
            continue
        __mods__['pkg_resource.add_pkg'](ret, pkg, ver)

    __mods__['pkg_resource.sort_pkglist'](ret)
    __context__['pkg.list_pkgs'] = copy.deepcopy(ret)
    if not versions_as_list:
        __mods__['pkg_resource.stringify'](ret)
    return ret

@memoize
def _check_pkgin():
    '''
    Looks to see if pkgin is present on the system, return full path
    '''
    ppath = hubblestack.utils.path.which('pkgin')
    if ppath is None:
        # pkgin was not found in $PATH, try to find it via LOCALBASE
        try:
            localbase = __mods__['cmd.run'](
               'pkg_info -Q LOCALBASE pkgin',
                output_loglevel='trace'
            )
            if localbase is not None:
                ppath = '{0}/bin/pkgin'.format(localbase)
                if not os.path.exists(ppath):
                    return None
        except CommandExecutionError:
            return None
    return ppath

def version(*names, **kwargs):
    '''
    Returns a string representing the package version or an empty string if not
    installed. If more than one package name is specified, a dict of
    name/version pairs is returned.
    '''
    return __mods__['pkg_resource.version'](*names, **kwargs)

def refresh_db(force=False):
    '''
    Use pkg update to get latest pkg_summary

    force
        Pass -f so that the cache is always refreshed.

        .. versionadded:: 2018.3.0
    '''
    # Remove rtag file to keep multiple refreshes from happening in pkg states
    hubblestack.utils.pkg.clear_rtag(__opts__)
    pkgin = _check_pkgin()

    if pkgin:
        cmd = [pkgin, 'up']
        if force:
            cmd.insert(1, '-f')
        call = __mods__['cmd.run_all'](cmd, output_loglevel='trace')

        if call['retcode'] != 0:
            comment = ''
            if 'stderr' in call:
                comment += call['stderr']

            raise CommandExecutionError(comment)

    return True
