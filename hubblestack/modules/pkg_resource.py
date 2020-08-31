# -*- coding: utf-8 -*-
'''
Resources needed by pkg providers
'''

# Import python libs
from __future__ import absolute_import, print_function, unicode_literals
import copy
import fnmatch
import logging
import os
import pprint

import hubblestack.utils.data

log = logging.getLogger(__name__)
__SUFFIX_NOT_NEEDED = ('x86_64', 'noarch')

def add_pkg(pkgs, name, pkgver):
    '''
    Add a package to a dict of installed packages.
    '''
    try:
        pkgs.setdefault(name, []).append(pkgver)
    except AttributeError as exc:
        log.exception(exc)

def format_pkg_list(packages, versions_as_list, attr):
    '''
    Formats packages according to parameters for list_pkgs.
    '''
    ret = copy.deepcopy(packages)
    if attr:
        requested_attr = {'epoch', 'version', 'release', 'arch', 'install_date', 'install_date_time_t'}

        if attr != 'all':
            requested_attr &= set(attr + ['version'])

        for name in ret:
            versions = []
            for all_attr in ret[name]:
                filtered_attr = {}
                for key in requested_attr:
                    if all_attr[key]:
                        filtered_attr[key] = all_attr[key]
                versions.append(filtered_attr)
            ret[name] = versions
        return ret

    for name in ret:
        ret[name] = [format_version(d['epoch'], d['version'], d['release'])
                     for d in ret[name]]
    if not versions_as_list:
        stringify(ret)
    return ret

def version(*names, **kwargs):
    '''
    Common interface for obtaining the version of installed packages.
    '''
    ret = {}
    versions_as_list = \
        hubblestack.utils.data.is_true(kwargs.pop('versions_as_list', False))
    pkg_glob = False
    if len(names) != 0:
        pkgs = __salt__['pkg.list_pkgs'](versions_as_list=True, **kwargs)
        for name in names:
            if '*' in name:
                pkg_glob = True
                for match in fnmatch.filter(pkgs, name):
                    ret[match] = pkgs.get(match, [])
            else:
                ret[name] = pkgs.get(name, [])
    if not versions_as_list:
        __salt__['pkg_resource.stringify'](ret)
    # Return a string if no globbing is used, and there is one item in the
    # return dict
    if len(ret) == 1 and not pkg_glob:
        try:
            return next(iter(ret.values()))
        except StopIteration:
            return ''
    return ret

def stringify(pkgs):
    '''
    Takes a dict of package name/version information and joins each list of
    installed versions into a string.
    '''
    try:
        for key in pkgs:
            pkgs[key] = ','.join(pkgs[key])
    except AttributeError as exc:
        log.exception(exc)

def sort_pkglist(pkgs):
    '''
    Accepts a dict obtained from pkg.list_pkgs() and sorts in place the list of
    versions for any packages that have multiple versions installed, so that
    two package lists can be compared to one another.
    '''
    # It doesn't matter that ['4.9','4.10'] would be sorted to ['4.10','4.9'],
    # so long as the sorting is consistent.
    try:
        for key in pkgs:
            # Passing the pkglist to set() also removes duplicate version
            # numbers (if present).
            pkgs[key] = sorted(set(pkgs[key]))
    except AttributeError as exc:
        log.exception(exc)

