# -*- coding: utf-8 -*-
'''
Support for apk

.. important::
    If you feel that Salt should be using this module to manage packages on a
    minion, and it is using a different module (or gives an error similar to
    *'pkg.install' is not available*), see :ref:`here
    <module-provider-override>`.

.. versionadded: 2017.7.0

'''

# Import python libs
import copy
import logging

# Import salt libs
import hubblestack.utils.data
import hubblestack.utils.itertools

from hubblestack.exceptions import CommandExecutionError

log = logging.getLogger(__name__)

# Define the module's virtual name
__virtualname__ = 'pkg'


def __virtual__():
    '''
    Confirm this module is running on an Alpine Linux distribution
    '''
    if __grains__.get('os_family', False) == 'Alpine':
        return __virtualname__
    return (False, "Module apk only works on Alpine Linux based systems")

def list_pkgs(versions_as_list=False, **kwargs):
    '''
    List the packages currently installed in a dict::

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

    cmd = ['apk', 'info', '-v']
    ret = {}
    out = __mods__['cmd.run'](cmd, output_loglevel='trace', python_shell=False)
    for line in hubblestack.utils.itertools.split(out, '\n'):
        pkg_version = '-'.join(line.split('-')[-2:])
        pkg_name = '-'.join(line.split('-')[:-2])
        __mods__['pkg_resource.add_pkg'](ret, pkg_name, pkg_version)

    __mods__['pkg_resource.sort_pkglist'](ret)
    __context__['pkg.list_pkgs'] = copy.deepcopy(ret)
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


def refresh_db():
    '''
    Updates the package list

    - ``True``: Database updated successfully
    - ``False``: Problem updating database
    '''
    ret = {}
    cmd = ['apk', 'update']
    call = __mods__['cmd.run_all'](cmd,
                                   output_loglevel='trace',
                                   python_shell=False)
    if call['retcode'] == 0:
        errors = []
        ret = True
    else:
        errors = [call['stdout']]
        ret = False

    if errors:
        raise CommandExecutionError(
            'Problem encountered installing package(s)',
            info={'errors': errors, 'changes': ret}
        )

    return ret
