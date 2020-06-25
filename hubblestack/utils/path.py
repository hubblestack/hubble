# -*- coding: utf-8 -*-
'''
Platform independent versions of some os/os.path functions. Gets around PY2's
lack of support for reading NTFS links.
'''

# Import python libs
import logging
import collections
import os
import posixpath
import re

import hubblestack.utils.stringutils
import hubblestack.utils.args
import hubblestack.utils.data
from hubblestack.utils.decorators.memoize import memoize

log = logging.getLogger(__name__)

def which(exe=None):
    '''
    Python clone of /usr/bin/which
    '''
    def _is_executable_file_or_link(exe):
        # check for os.X_OK doesn't suffice because directory may executable
        return (os.access(exe, os.X_OK) and
                (os.path.isfile(exe) or os.path.islink(exe)))

    if exe:
        if _is_executable_file_or_link(exe):
            # executable in cwd or fullpath
            return exe

        ext_list = hubblestack.utils.stringutils.to_str(
            os.environ.get('PATHEXT', str('.EXE'))
        ).split(str(';'))

        @memoize
        def _exe_has_ext():
            '''
            Do a case insensitive test if exe has a file extension match in
            PATHEXT
            '''
            for ext in ext_list:
                try:
                    pattern = r'.*\.{0}$'.format(
                        hubblestack.utils.stringutils.to_unicode(ext).lstrip('.')
                    )
                    re.match(
                        pattern,
                        hubblestack.utils.stringutils.to_unicode(exe),
                        re.I).groups()
                    return True
                except AttributeError:
                    continue
            return False

        # Enhance POSIX path for the reliability at some environments, when $PATH is changing
        # This also keeps order, where 'first came, first win' for cases to find optional alternatives
        system_path = hubblestack.utils.stringutils.to_unicode(os.environ.get('PATH', ''))
        search_path = system_path.split(os.pathsep)
        if not hubblestack.utils.platform.is_windows():
            search_path.extend([
                x for x in ('/bin', '/sbin', '/usr/bin',
                            '/usr/sbin', '/usr/local/bin')
                if x not in search_path
            ])

        for path in search_path:
            full_path = join(path, exe)
            if _is_executable_file_or_link(full_path):
                return full_path
            elif hubblestack.utils.platform.is_windows() and not _exe_has_ext():
                # On Windows, check for any extensions in PATHEXT.
                # Allows both 'cmd' and 'cmd.exe' to be matched.
                for ext in ext_list:
                    # Windows filesystem is case insensitive so we
                    # safely rely on that behavior
                    if _is_executable_file_or_link(full_path + ext):
                        return full_path + ext
        log.trace(
            '\'%s\' could not be found in the following search path: \'%s\'',
            exe, search_path
        )
    else:
        log.error('No executable was passed to be searched by hubblestack.utils.path.which()')

    return None

def which_bin(exes):
    '''
    Scan over some possible executables and return the first one that is found
    '''
    if not isinstance(exes, collections.Iterable):
        return None
    for exe in exes:
        path = which(exe)
        if not path:
            continue
        return path
    return None

def join(*parts, **kwargs):
    '''
    This functions tries to solve some issues when joining multiple absolute
    paths on both *nix and windows platforms.

    The "use_posixpath" kwarg can be be used to force joining using poxixpath,
    which is useful for fileserver paths on Windows
    '''
    new_parts = []
    for part in parts:
        new_parts.append(hubblestack.utils.stringutils.to_str(part))
    parts = new_parts

    kwargs = hubblestack.utils.args.clean_kwargs(**kwargs)
    use_posixpath = kwargs.pop('use_posixpath', False)
    if kwargs:
        hubblestack.utils.args.invalid_kwargs(kwargs)

    pathlib = posixpath if use_posixpath else os.path

    # Normalize path converting any os.sep as needed
    parts = [pathlib.normpath(p) for p in parts]

    try:
        root = parts.pop(0)
    except IndexError:
        # No args passed to func
        return ''

    root = hubblestack.utils.stringutils.to_unicode(root)
    if not parts:
        ret = root
    else:
        stripped = [p.lstrip(os.sep) for p in parts]
        ret = pathlib.join(root, *hubblestack.utils.data.decode(stripped))
    return pathlib.normpath(ret)

def islink(path):
    '''
    call to os.path.islink()
    '''
    return os.path.islink(path)

def readlink(path):
    '''
    call to os.readlink()
    '''
    return os.readlink(path)

def os_walk(top, *args, **kwargs):
    '''
    This is a helper than ensures that all paths returned from os.walk are
    unicode.
    '''
    top_query = hubblestack.utils.stringutils.to_str(top)
    for item in os.walk(top_query, *args, **kwargs):
        yield hubblestack.utils.data.decode(item, preserve_tuples=True)

