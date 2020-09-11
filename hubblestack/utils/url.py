# -*- coding: utf-8 -*-
'''
URL utils
'''

# Import python libs
from __future__ import absolute_import, print_function, unicode_literals
import re

# Import salt libs
from urllib.parse import urlparse, urlunparse  # pylint: disable=import-error,no-name-in-module
import hubblestack.utils.path
import hubblestack.utils.platform


def parse(url):
    '''
    Parse a salt:// URL; return the path and a possible saltenv query.
    '''
    if not url.startswith('salt://'):
        return url, None

    # urlparse will split on valid filename chars such as '?' and '&'
    resource = url.split('salt://', 1)[-1]

    if '?env=' in resource:
        # "env" is not supported; Use "saltenv".
        path, saltenv = resource.split('?env=', 1)[0], None
    elif '?saltenv=' in resource:
        path, saltenv = resource.split('?saltenv=', 1)
    else:
        path, saltenv = resource, None

    if hubblestack.utils.platform.is_windows():
        path = hubblestack.utils.path.sanitize_win_path(path)

    return path, saltenv


def create(path, saltenv=None):
    '''
    join `path` and `saltenv` into a 'salt://' URL.
    '''
    if hubblestack.utils.platform.is_windows():
        path = hubblestack.utils.path.sanitize_win_path(path)
    path = hubblestack.utils.data.decode(path)

    query = 'saltenv={0}'.format(saltenv) if saltenv else ''
    url = hubblestack.utils.data.decode(urlunparse(('file', '', path, '', query, '')))
    return 'salt://{0}'.format(url[len('file:///'):])


def is_escaped(url):
    '''
    test whether `url` is escaped with `|`
    '''
    scheme = urlparse(url).scheme
    if not scheme:
        return url.startswith('|')
    elif scheme == 'salt':
        path, saltenv = parse(url)
        if hubblestack.utils.platform.is_windows() and '|' in url:
            return path.startswith('_')
        else:
            return path.startswith('|')
    else:
        return False


def escape(url):
    '''
    add escape character `|` to `url`
    '''
    if hubblestack.utils.platform.is_windows():
        return url

    scheme = urlparse(url).scheme
    if not scheme:
        if url.startswith('|'):
            return url
        else:
            return '|{0}'.format(url)
    elif scheme == 'salt':
        path, saltenv = parse(url)
        if path.startswith('|'):
            return create(path, saltenv)
        else:
            return create('|{0}'.format(path), saltenv)
    else:
        return url


def unescape(url):
    '''
    remove escape character `|` from `url`
    '''
    scheme = urlparse(url).scheme
    if not scheme:
        return url.lstrip('|')
    elif scheme == 'salt':
        path, saltenv = parse(url)
        if hubblestack.utils.platform.is_windows() and '|' in url:
            return create(path.lstrip('_'), saltenv)
        else:
            return create(path.lstrip('|'), saltenv)
    else:
        return url


def split_env(url):
    '''
    remove the saltenv query parameter from a 'salt://' url
    '''
    if not url.startswith('salt://'):
        return url, None

    path, senv = parse(url)
    return create(path), senv


def strip_proto(url):
    '''
    Return a copy of the string with the protocol designation stripped, if one
    was present.
    '''
    return re.sub('^[^:/]+://', '', url)