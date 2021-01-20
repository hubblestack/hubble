"""
Minion side functions for salt-cp
"""

# Import python libs
import logging
import os
from urllib.parse import urlparse

import hubblestack.fileclient
import hubblestack.utils.data
import hubblestack.utils.files
import hubblestack.utils.url

log = logging.getLogger(__name__)

__proxyenabled__ = ["*"]


def _mk_client():
    """
    Create a file client and add it to the context.

    Each file client needs to correspond to a unique copy
    of the opts dictionary, therefore it's hashed by the
    id of the __opts__ dict
    """
    if "cp.fileclient_{}".format(id(__opts__)) not in __context__:
        __context__[
            "cp.fileclient_{}".format(id(__opts__))
        ] = hubblestack.fileclient.get_file_client(__opts__)


def _client():
    """
    Return a client, hashed by the list of masters
    """
    _mk_client()
    return __context__["cp.fileclient_{}".format(id(__opts__))]

def get_file(path,
             dest,
             saltenv='base',
             makedirs=False,
             gzip=None,
             **kwargs):
    '''
    Used to get a single file on the minion
    CLI Example:
    .. code-block:: bash
        salt '*' cp.get_file salt://path/to/file /minion/dest
    
    .. note::
        It may be necessary to quote the URL when using the querystring method,
        depending on the shell being used to run the command.
    '''
    path, senv = hubblestack.utils.url.split_env(path)
    if senv:
        saltenv = senv

    if not hash_file(path, saltenv):
        return ''
    else:
        return _client().get_file(
                path,
                dest,
                makedirs,
                saltenv,
                gzip)

def hash_file(path, saltenv='base'):
    '''
    Return the hash of a file, to get the hash of a file on the
    salt master file server prepend the path with salt://<file on server>
    otherwise, prepend the file with / for a local file.

    CLI Example:

    .. code-block:: bash

        salt '*' cp.hash_file salt://path/to/file
    '''
    path, senv = hubblestack.utils.url.split_env(path)
    if senv:
        saltenv = senv

    return _client().hash_file(path, saltenv)

def cache_file(path, saltenv="base", source_hash=None):
    """
    Used to cache a single file on the Minion

    Returns the location of the new cached file on the Minion

    source_hash
        If ``name`` is an http(s) or ftp URL and the file exists in the
        minion's file cache, this option can be passed to keep the minion from
        re-downloading the file if the cached copy matches the specified hash.

        .. versionadded:: 2018.3.0

    CLI Example:

    .. code-block:: bash

        salt '*' cp.cache_file salt://path/to/file

    There are two ways of defining the fileserver environment (a.k.a.
    ``saltenv``) from which to cache the file. One is to use the ``saltenv``
    parameter, and the other is to use a querystring syntax in the ``salt://``
    URL. The below two examples are equivalent:

    .. code-block:: bash

        salt '*' cp.cache_file salt://foo/bar.conf saltenv=config
        salt '*' cp.cache_file salt://foo/bar.conf?saltenv=config

    If the path being cached is a ``salt://`` URI, and the path does not exist,
    then ``False`` will be returned.

    .. note::
        It may be necessary to quote the URL when using the querystring method,
        depending on the shell being used to run the command.
    """
    path = hubblestack.utils.data.decode(path)
    saltenv = hubblestack.utils.data.decode(saltenv)

    contextkey = "{}_|-{}_|-{}".format("cp.cache_file", path, saltenv)

    path_is_remote = urlparse(path).scheme in hubblestack.utils.files.REMOTE_PROTOS
    try:
        if path_is_remote and contextkey in __context__:
            # Prevent multiple caches in the same salt run. Affects remote URLs
            # since the master won't know their hash, so the fileclient
            # wouldn't be able to prevent multiple caches if we try to cache
            # the remote URL more than once.
            if os.path.isfile(__context__[contextkey]):
                return __context__[contextkey]
            else:
                # File is in __context__ but no longer exists in the minion
                # cache, get rid of the context key and re-cache below.
                # Accounts for corner case where file is removed from minion
                # cache between cp.cache_file calls in the same salt-run.
                __context__.pop(contextkey)
    except AttributeError:
        pass

    path, senv = hubblestack.utils.url.split_env(path)
    if senv:
        saltenv = senv
    result = _client().cache_file(path, saltenv, source_hash=source_hash)
    if not result:
        log.error("Unable to cache file '%s' from saltenv '%s'.", path, saltenv)
    if path_is_remote:
        # Cache was successful, store the result in __context__ to prevent
        # multiple caches (see above).
        __context__[contextkey] = result
    return result


def cache_dir(
    path, saltenv="base", include_empty=False, include_pat=None, exclude_pat=None
):
    """
    Download and cache everything under a directory from the master


    include_pat : None
        Glob or regex to narrow down the files cached from the given path. If
        matching with a regex, the regex must be prefixed with ``E@``,
        otherwise the expression will be interpreted as a glob.

        .. versionadded:: 2014.7.0

    exclude_pat : None
        Glob or regex to exclude certain files from being cached from the given
        path. If matching with a regex, the regex must be prefixed with ``E@``,
        otherwise the expression will be interpreted as a glob.

        .. note::

            If used with ``include_pat``, files matching this pattern will be
            excluded from the subset of files defined by ``include_pat``.

        .. versionadded:: 2014.7.0


    CLI Examples:

    .. code-block:: bash

        salt '*' cp.cache_dir salt://path/to/dir
        salt '*' cp.cache_dir salt://path/to/dir include_pat='E@*.py$'
    """
    return _client().cache_dir(path, saltenv, include_empty, include_pat, exclude_pat)
