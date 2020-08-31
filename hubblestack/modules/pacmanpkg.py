# -*- coding: utf-8 -*-
'''
A module to wrap pacman calls, since Arch is the best
(https://wiki.archlinux.org/index.php/Arch_is_the_best)

.. important::
    If you feel that Salt should be using this module to manage packages on a
    minion, and it is using a different module (or gives an error similar to
    *'pkg.install' is not available*), see :ref:`here
    <module-provider-override>`.
'''

# Import python libs
from __future__ import absolute_import, print_function, unicode_literals
import copy
import fnmatch
import logging
import os.path

# Import salt libs
import hubblestack.utils.data
import hubblestack.utils.itertools
import hubblestack.utils.pkg
from hubblestack.utils.exceptions import CommandExecutionError

log = logging.getLogger(__name__)

# Define the module's virtual name
__virtualname__ = 'pkg'


def __virtual__():
    '''
    Set the virtual pkg module if the os is Arch
    '''
    if __grains__['os_family'] == 'Arch':
        return __virtualname__
    return (False, 'The pacman module could not be loaded: unsupported OS family.')

def list_pkgs(versions_as_list=False, **kwargs):
    '''
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
            __salt__['pkg_resource.stringify'](ret)
            return ret

    cmd = ['pacman', '-Q']

    if 'root' in kwargs:
        cmd.extend(('-r', kwargs['root']))

    ret = {}
    out = __salt__['cmd.run'](cmd, output_loglevel='trace', python_shell=False)
    for line in hubblestack.utils.itertools.split(out, '\n'):
        if not line:
            continue
        try:
            name, version_num = line.split()[0:2]
        except ValueError:
            log.error('Problem parsing pacman -Q: Unexpected formatting in '
                      'line: \'%s\'', line)
        else:
            __salt__['pkg_resource.add_pkg'](ret, name, version_num)

    __salt__['pkg_resource.sort_pkglist'](ret)
    __context__['pkg.list_pkgs'] = copy.deepcopy(ret)
    if not versions_as_list:
        __salt__['pkg_resource.stringify'](ret)
    return ret

def version(*names, **kwargs):
    '''
    Returns a string representing the package version or an empty string if not
    installed. If more than one package name is specified, a dict of
    name/version pairs is returned.
    '''
    return __salt__['pkg_resource.version'](*names, **kwargs)

def refresh_db(root=None):
    '''
    Just run a ``pacman -Sy``, return a dict::

        {'<database name>': Bool}
    '''
    # Remove rtag file to keep multiple refreshes from happening in pkg states
    hubblestack.utils.pkg.clear_rtag(__opts__)
    cmd = ['pacman', '-Sy']

    if root is not None:
        cmd.extend(('-r', root))

    ret = {}
    call = __salt__['cmd.run_all'](cmd,
                                   output_loglevel='trace',
                                   env={'LANG': 'C'},
                                   python_shell=False)
    if call['retcode'] != 0:
        comment = ''
        if 'stderr' in call:
            comment += ': ' + call['stderr']
        raise CommandExecutionError(
            'Error refreshing package database' + comment
        )
    else:
        out = call['stdout']

    for line in hubblestack.utils.itertools.split(out, '\n'):
        if line.strip().startswith('::'):
            continue
        if not line:
            continue
        key = line.strip().split()[0]
        if 'is up to date' in line:
            ret[key] = False
        elif 'downloading' in line:
            key = line.strip().split()[1].split('.')[0]
            ret[key] = True
    return ret
