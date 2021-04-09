# -*- coding: utf-8 -*-
'''
A module to manage software on Windows

.. important::
    If you feel that hubblestack should be using this module to manage packages on a
    minion, and it is using a different module (or gives an error similar to
    *'pkg.install' is not available*), see :ref:`here
    <module-provider-override>`.

The following functions require the existence of a :ref:`windows repository
<windows-package-manager>` metadata DB, typically created by running
:py:func:`pkg.refresh_db <hubblestack.modules.win_pkg.refresh_db>`:

- :py:func:`pkg.get_repo_data <hubblestack.modules.win_pkg.get_repo_data>`
- :py:func:`pkg.install <hubblestack.modules.win_pkg.install>`
- :py:func:`pkg.latest_version <hubblestack.modules.win_pkg.latest_version>`
- :py:func:`pkg.list_available <hubblestack.modules.win_pkg.list_available>`
- :py:func:`pkg.list_pkgs <hubblestack.modules.win_pkg.list_pkgs>`
- :py:func:`pkg.list_upgrades <hubblestack.modules.win_pkg.list_upgrades>`
- :py:func:`pkg.remove <hubblestack.modules.win_pkg.remove>`

If a metadata DB does not already exist and one of these functions is run, then
one will be created from the repo SLS files that are present.

As the creation of this metadata can take some time, the
:conf_minion:`winrepo_cache_expire_min` minion config option can be used to
suppress refreshes when the metadata is less than a given number of seconds
old.

.. note::
    Version numbers can be ``version number string``, ``latest`` and ``Not
    Found``, where ``Not Found`` means this module was not able to determine
    the version of the software installed, it can also be used as the version
    number in sls definitions file in these cases. Versions numbers are sorted
    in order of 0, ``Not Found``, ``order version numbers``, ..., ``latest``.

'''

# Import python future libs
import collections
import datetime
import errno
import logging
import os
import re
import time
import sys
from functools import cmp_to_key

from urllib.parse import urlparse

# Import salt libs
from hubblestack.exceptions import (CommandExecutionError,
                             HubbleRenderError)
import hubblestack.utils.data
import hubblestack.utils.files
import hubblestack.utils.path
import hubblestack.utils.pkg
import hubblestack.utils.platform
import hubblestack.utils.win_functions
import hubblestack.template
import hubblestack.payload
from urllib.parse import urlparse

log = logging.getLogger(__name__)

# Define the module's virtual name
__virtualname__ = 'pkg'


def __virtual__():
    '''
    Set the virtual pkg module if the os is Windows
    '''
    if hubblestack.utils.platform.is_windows():
        return __virtualname__
    return (False, "Module win_pkg: module only works on Windows systems")

def list_pkgs(versions_as_list=False,
              include_components=True,
              include_updates=True,
              **kwargs):
    '''
    List the packages currently installed.

    .. note::
        To view installed software as displayed in the Add/Remove Programs, set
        ``include_components`` and ``include_updates`` to False.

    Args:

        versions_as_list (bool):
            Returns the versions as a list

        include_components (bool):
            Include sub components of installed software. Default is ``True``

        include_updates (bool):
            Include software updates and Windows updates. Default is ``True``

    Kwargs:

        saltenv (str):
            The salt environment to use. Default ``base``

        refresh (bool):
            Refresh package metadata. Default ``False``

    Returns:
        dict: A dictionary of installed software with versions installed

    .. code-block:: cfg

        {'<package_name>': '<version>'}
    '''
    versions_as_list = hubblestack.utils.data.is_true(versions_as_list)
    # not yet implemented or not applicable
    if any([hubblestack.utils.data.is_true(kwargs.get(x))
            for x in ('removed', 'purge_desired')]):
        return {}
    saltenv = kwargs.get('saltenv', 'base')
    refresh = hubblestack.utils.data.is_true(kwargs.get('refresh', False))
    _refresh_db_conditional(saltenv, force=refresh)

    ret = {}
    name_map = _get_name_map(saltenv)
    for pkg_name, val_list in iter(
            _get_reg_software(include_components=include_components,
                              include_updates=include_updates).items()):
        if pkg_name in name_map:
            key = name_map[pkg_name]
            for val in val_list:
                if val == 'Not Found':
                    # Look up version from winrepo
                    pkg_info = _get_package_info(key, saltenv=saltenv)
                    if not pkg_info:
                        continue
                    for pkg_ver in pkg_info.keys():
                        if pkg_info[pkg_ver]['full_name'] == pkg_name:
                            val = pkg_ver
                __mods__['pkg_resource.add_pkg'](ret, key, val)
        else:
            key = pkg_name
            for val in val_list:
                __mods__['pkg_resource.add_pkg'](ret, key, val)

    __mods__['pkg_resource.sort_pkglist'](ret)
    if not versions_as_list:
        __mods__['pkg_resource.stringify'](ret)
    return ret

def _refresh_db_conditional(saltenv, **kwargs):
    '''
    Internal use only in this module, has a different set of defaults and
    returns True or False. And supports checking the age of the existing
    generated metadata db, as well as ensure metadata db exists to begin with

    Args:
        saltenv (str): Salt environment

    Kwargs:

        force (bool):
            Force a refresh if the minimum age has been reached. Default is
            False.

        failhard (bool):
            If ``True``, an error will be raised if any repo SLS files failed to
            process.

    Returns:
        bool: True Fetched or Cache uptodate, False to indicate an issue

    :codeauthor: Damon Atkins <https://github.com/damon-atkins>
    '''
    force = hubblestack.utils.data.is_true(kwargs.pop('force', False))
    failhard = hubblestack.utils.data.is_true(kwargs.pop('failhard', False))
    expired_max = __opts__['winrepo_cache_expire_max']
    expired_min = __opts__['winrepo_cache_expire_min']

    repo_details = _get_repo_details(saltenv)

    # Skip force if age less than minimum age
    if force and expired_min > 0 and repo_details.winrepo_age < expired_min:
        log.info(
            'Refresh skipped, age of winrepo metadata in seconds (%s) is less '
            'than winrepo_cache_expire_min (%s)',
            repo_details.winrepo_age, expired_min
        )
        force = False

    # winrepo_age is -1 if repo db does not exist
    refresh = True if force \
        or repo_details.winrepo_age == -1 \
        or repo_details.winrepo_age > expired_max \
        else False

    if not refresh:
        log.debug(
            'Using existing pkg metadata db for saltenv \'%s\' (age is %s)',
            saltenv, datetime.timedelta(seconds=repo_details.winrepo_age)
        )
        return True

    if repo_details.winrepo_age == -1:
        # no repo meta db
        log.debug(
            'No winrepo.p cache file for saltenv \'%s\', creating one now',
            saltenv
        )

    results = refresh_db(saltenv=saltenv, verbose=False, failhard=failhard)
    try:
        # Return True if there were no failed winrepo SLS files, and False if
        # failures were reported.
        return not bool(results.get('failed', 0))
    except AttributeError:
        return False

def refresh_db(**kwargs):
    r'''
    Generates the local software metadata database (`winrepo.p`) on the minion.
    The database is stored in a serialized format located by default at the
    following location:

    ``C:\salt\var\cache\salt\minion\files\base\win\repo-ng\winrepo.p``

    This module performs the following steps to generate the software metadata
    database:

    - Fetch the package definition files (.sls) from `winrepo_source_dir`
      (default `salt://win/repo-ng`) and cache them in
      `<cachedir>\files\<saltenv>\<winrepo_source_dir>`
      (default: ``C:\salt\var\cache\salt\minion\files\base\win\repo-ng``)
    - Call :py:func:`pkg.genrepo <hubblestack.modules.win_pkg.genrepo>` to parse the
      package definition files and generate the repository metadata database
      file (`winrepo.p`)
    - Return the report received from
      :py:func:`pkg.genrepo <hubblestack.modules.win_pkg.genrepo>`

    The default winrepo directory on the master is `/srv/salt/win/repo-ng`. All
    files that end with `.sls` in this and all subdirectories will be used to
    generate the repository metadata database (`winrepo.p`).

    .. note::
        - Hidden directories (directories beginning with '`.`', such as
          '`.git`') will be ignored.

    .. note::
        There is no need to call `pkg.refresh_db` every time you work with the
        pkg module. Automatic refresh will occur based on the following minion
        configuration settings:

        - `winrepo_cache_expire_min`
        - `winrepo_cache_expire_max`

        However, if the package definition files have changed, as would be the
        case if you are developing a new package definition, this function
        should be called to ensure the minion has the latest information about
        packages available to it.

    .. warning::
        Directories and files fetched from <winrepo_source_dir>
        (`/srv/salt/win/repo-ng`) will be processed in alphabetical order. If
        two or more software definition files contain the same name, the last
        one processed replaces all data from the files processed before it.

    For more information see
    :ref:`Windows Software Repository <windows-package-manager>`

    Arguments:

    saltenv (str): Salt environment. Default: ``base``

    verbose (bool):
        Return a verbose data structure which includes 'success_list', a
        list of all sls files and the package names contained within.
        Default is 'False'

    failhard (bool):
        If ``True``, an error will be raised if any repo SLS files fails to
        process. If ``False``, no error will be raised, and a dictionary
        containing the full results will be returned.

    Returns:
        dict: A dictionary containing the results of the database refresh.

    .. note::
        A result with a `total: 0` generally means that the files are in the
        wrong location on the master. Try running the following command on the
        minion: `salt-call -l debug pkg.refresh saltenv=base`

    .. warning::
        When calling this command from a state using `module.run` be sure to
        pass `failhard: False`. Otherwise the state will report failure if it
        encounters a bad software definition file.
    '''
    # Remove rtag file to keep multiple refreshes from happening in pkg states
    hubblestack.utils.pkg.clear_rtag(__opts__)
    saltenv = kwargs.pop('saltenv', 'base')
    verbose = hubblestack.utils.data.is_true(kwargs.pop('verbose', False))
    failhard = hubblestack.utils.data.is_true(kwargs.pop('failhard', True))
    __context__.pop('winrepo.data', None)
    repo_details = _get_repo_details(saltenv)

    log.debug(
        'Refreshing pkg metadata db for saltenv \'%s\' (age of existing '
        'metadata is %s)',
        saltenv, datetime.timedelta(seconds=repo_details.winrepo_age)
    )

    # Clear minion repo-ng cache see #35342 discussion
    log.info('Removing all *.sls files under \'%s\'', repo_details.local_dest)
    failed = []
    for root, _, files in hubblestack.utils.path.os_walk(repo_details.local_dest, followlinks=False):
        for name in files:
            if name.endswith('.sls'):
                full_filename = os.path.join(root, name)
                try:
                    os.remove(full_filename)
                except OSError as exc:
                    if exc.errno != errno.ENOENT:
                        log.error('Failed to remove %s: %s', full_filename, exc)
                        failed.append(full_filename)
    if failed:
        raise CommandExecutionError(
            'Failed to clear one or more winrepo cache files',
            info={'failed': failed}
        )

    # Cache repo-ng locally
    log.info('Fetching *.sls files from {0}'.format(repo_details.winrepo_source_dir))
    __mods__['cp.cache_dir'](
        path=repo_details.winrepo_source_dir,
        saltenv=saltenv,
        include_pat='*.sls',
        exclude_pat=r'E@\/\..*?\/'  # Exclude all hidden directories (.git)
    )
    return genrepo(saltenv=saltenv, verbose=verbose, failhard=failhard)

def _get_name_map(saltenv='base'):
    '''
    Return a reverse map of full pkg names to the names recognized by winrepo.
    '''
    u_name_map = {}
    name_map = get_repo_data(saltenv).get('name_map', {})

    for k in name_map:
        u_name_map[k] = name_map[k]
    return u_name_map

def get_repo_data(saltenv='base'):
    '''
    Returns the existing package metadata db. Will create it, if it does not
    exist, however will not refresh it.

    Args:
        saltenv (str): Salt environment. Default ``base``

    Returns:
        dict: A dict containing contents of metadata db.
    '''
    # we only call refresh_db if it does not exist, as we want to return
    # the existing data even if its old, other parts of the code call this,
    # but they will call refresh if they need too.
    repo_details = _get_repo_details(saltenv)

    if repo_details.winrepo_age == -1:
        # no repo meta db
        log.debug('No winrepo.p cache file. Refresh pkg db now.')
        refresh_db(saltenv=saltenv)

    if 'winrepo.data' in __context__:
        log.trace('get_repo_data returning results from __context__')
        return __context__['winrepo.data']
    else:
        log.trace('get_repo_data called reading from disk')

    try:
        serial = hubblestack.payload.Serial(__opts__)
        with hubblestack.utils.files.fopen(repo_details.winrepo_file, 'rb') as repofile:
            try:
                repodata = hubblestack.utils.data.decode(serial.loads(repofile.read()) or {})
                __context__['winrepo.data'] = repodata
                return repodata
            except Exception as exc:
                log.exception(exc)
                return {}
    except IOError as exc:
        log.error('Not able to read repo file')
        log.exception(exc)
        return {}

def _get_repo_details(saltenv):
    '''
    Return repo details for the specified saltenv as a namedtuple
    '''
    contextkey = 'winrepo._get_repo_details.{0}'.format(saltenv)

    if contextkey in __context__:
        (winrepo_source_dir, local_dest, winrepo_file) = __context__[contextkey]
    else:
        winrepo_source_dir = __opts__['winrepo_source_dir']
        dirs = [__opts__['cachedir'], 'files', saltenv]
        url_parts = urlparse(winrepo_source_dir)
        dirs.append(url_parts.netloc)
        dirs.extend(url_parts.path.strip('/').split('/'))
        local_dest = os.sep.join(dirs)

        winrepo_file = os.path.join(local_dest, 'winrepo.p')  # Default
        # Check for a valid windows file name
        if not re.search(r'[\/:*?"<>|]',
                         __opts__['winrepo_cachefile'],
                         flags=re.IGNORECASE):
            winrepo_file = os.path.join(
                local_dest,
                __opts__['winrepo_cachefile']
                )
        else:
            log.error(
                'minion configuration option \'winrepo_cachefile\' has been '
                'ignored as its value (%s) is invalid. Please ensure this '
                'option is set to a valid filename.',
                __opts__['winrepo_cachefile']
            )

        # Do some safety checks on the repo_path as its contents can be removed,
        # this includes check for bad coding
        system_root = os.environ.get('SystemRoot', r'C:\Windows')
        if not hubblestack.utils.path.safe_path(
                path=local_dest,
                allow_path='\\'.join([system_root, 'TEMP'])):

            raise CommandExecutionError(
                'Attempting to delete files from a possibly unsafe location: '
                '{0}'.format(local_dest)
            )

        __context__[contextkey] = (winrepo_source_dir, local_dest, winrepo_file)

    try:
        os.makedirs(local_dest)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise CommandExecutionError(
                'Failed to create {0}: {1}'.format(local_dest, exc)
            )

    winrepo_age = -1
    try:
        stat_result = os.stat(winrepo_file)
        mtime = stat_result.st_mtime
        winrepo_age = time.time() - mtime
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            raise CommandExecutionError(
                'Failed to get age of {0}: {1}'.format(winrepo_file, exc)
            )
    except AttributeError:
        # Shouldn't happen but log if it does
        log.warning('st_mtime missing from stat result %s', stat_result)
    except TypeError:
        # Shouldn't happen but log if it does
        log.warning('mtime of %s (%s) is an invalid type', winrepo_file, mtime)

    repo_details = collections.namedtuple(
        'RepoDetails',
        ('winrepo_source_dir', 'local_dest', 'winrepo_file', 'winrepo_age')
    )
    return repo_details(winrepo_source_dir, local_dest, winrepo_file, winrepo_age)

def genrepo(**kwargs):
    '''
    Generate package metadata db based on files within the winrepo_source_dir

    Kwargs:

        saltenv (str): Salt environment. Default: ``base``

        verbose (bool):
            Return verbose data structure which includes 'success_list', a list
            of all sls files and the package names contained within.
            Default ``False``.

        failhard (bool):
            If ``True``, an error will be raised if any repo SLS files failed
            to process. If ``False``, no error will be raised, and a dictionary
            containing the full results will be returned.

    .. note::
        - Hidden directories (directories beginning with '`.`', such as
          '`.git`') will be ignored.

    Returns:
        dict: A dictionary of the results of the command
    '''
    saltenv = kwargs.pop('saltenv', 'base')
    verbose = hubblestack.utils.data.is_true(kwargs.pop('verbose', False))
    failhard = hubblestack.utils.data.is_true(kwargs.pop('failhard', True))

    ret = {}
    successful_verbose = {}
    total_files_processed = 0
    ret['repo'] = {}
    ret['errors'] = {}
    repo_details = _get_repo_details(saltenv)

    for root, _, files in hubblestack.utils.path.os_walk(repo_details.local_dest, followlinks=False):

        # Skip hidden directories (.git)
        if re.search(r'[\\/]\..*', root):
            log.debug('Skipping files in directory: {0}'.format(root))
            continue

        short_path = os.path.relpath(root, repo_details.local_dest)
        if short_path == '.':
            short_path = ''

        for name in files:
            if name.endswith('.sls'):
                total_files_processed += 1
                _repo_process_pkg_sls(
                    os.path.join(root, name),
                    os.path.join(short_path, name),
                    ret,
                    successful_verbose
                    )
    serial = hubblestack.payload.Serial(__opts__)

    with hubblestack.utils.files.fopen(repo_details.winrepo_file, 'wb') as repo_cache:
        repo_cache.write(serial.dumps(ret))
    # For some reason we can not save ret into __context__['winrepo.data'] as this breaks due to utf8 issues
    successful_count = len(successful_verbose)
    error_count = len(ret['errors'])
    if verbose:
        results = {
            'total': total_files_processed,
            'success': successful_count,
            'failed': error_count,
            'success_list': successful_verbose,
            'failed_list': ret['errors']
            }
    else:
        if error_count > 0:
            results = {
                'total': total_files_processed,
                'success': successful_count,
                'failed': error_count,
                'failed_list': ret['errors']
                }
        else:
            results = {
                'total': total_files_processed,
                'success': successful_count,
                'failed': error_count
                }

    if error_count > 0 and failhard:
        raise CommandExecutionError(
            'Error occurred while generating repo db',
            info=results
        )
    else:
        return results

def _repo_process_pkg_sls(filename, short_path_name, ret, successful_verbose):
    renderers = hubblestack.loader.render(__opts__, __mods__)

    def _failed_compile(prefix_msg, error_msg):
        log.error('{0} \'{1}\': {2} '.format(prefix_msg, short_path_name, error_msg))
        ret.setdefault('errors', {})[short_path_name] = ['{0}, {1} '.format(prefix_msg, error_msg)]
        return False

    try:
        config = hubblestack.template.compile_template(
            filename,
            renderers,
            __opts__['renderer'],
            __opts__.get('renderer_blacklist', ''),
            __opts__.get('renderer_whitelist', ''))
    except SaltRenderError as exc:
        return _failed_compile('Failed to compile', exc)
    except Exception as exc:
        return _failed_compile('Failed to read', exc)

    if config and isinstance(config, dict):
        revmap = {}
        errors = []
        for pkgname, version_list in iter(config.items()):
            if pkgname in ret['repo']:
                log.error(
                    'package \'%s\' within \'%s\' already defined, skipping',
                    pkgname, short_path_name
                )
                errors.append('package \'{0}\' already defined'.format(pkgname))
                break
            for version_str, repodata in iter(version_list.items()):
                # Ensure version is a string/unicode
                if not isinstance(version_str, str):
                    log.error(
                        "package '%s' within '%s', version number %s' "
                        "is not a string",
                        pkgname, short_path_name, version_str
                    )
                    errors.append(
                        'package \'{0}\', version number {1} '
                        'is not a string'.format(pkgname, version_str)
                    )
                    continue
                # Ensure version contains a dict
                if not isinstance(repodata, dict):
                    log.error(
                        "package '%s' within '%s', repo data for "
                        'version number %s is not defined as a dictionary',
                        pkgname, short_path_name, version_str
                    )
                    errors.append(
                        'package \'{0}\', repo data for '
                        'version number {1} is not defined as a dictionary'
                        .format(pkgname, version_str)
                    )
                    continue
                revmap[repodata['full_name']] = pkgname
        if errors:
            ret.setdefault('errors', {})[short_path_name] = errors
        else:
            ret.setdefault('repo', {}).update(config)
            ret.setdefault('name_map', {}).update(revmap)
            successful_verbose[short_path_name] = list(config.keys())
    elif config:
        return _failed_compile('Compiled contents', 'not a dictionary/hash')
    else:
        log.debug('No data within \'%s\' after processing', short_path_name)
        # no pkgname found after render
        successful_verbose[short_path_name] = []

def version(*names, **kwargs):
    '''
    Returns a string representing the package version or an empty string if not
    installed. If more than one package name is specified, a dict of
    name/version pairs is returned.

    Args:
        name (str): One or more package names

    Kwargs:
        saltenv (str): The salt environment to use. Default ``base``.
        refresh (bool): Refresh package metadata. Default ``False``.

    Returns:
        str: version string when a single package is specified.
        dict: The package name(s) with the installed versions.

    .. code-block:: cfg

        {['<version>', '<version>', ]} OR
        {'<package name>': ['<version>', '<version>', ]}
    '''
    # Standard is return empty string even if not a valid name
    # TODO: Look at returning an error across all platforms with
    # CommandExecutionError(msg,info={'errors': errors })
    # available_pkgs = get_repo_data(saltenv).get('repo')
    # for name in names:
    #    if name in available_pkgs:
    #        ret[name] = installed_pkgs.get(name, '')

    saltenv = kwargs.get('saltenv', 'base')
    installed_pkgs = list_pkgs(saltenv=saltenv, refresh=kwargs.get('refresh', False))

    if len(names) == 1:
        return installed_pkgs.get(names[0], '')

    ret = {}
    for name in names:
        ret[name] = installed_pkgs.get(name, '')
    return ret

def _get_reg_software(include_components=True,
                      include_updates=True):
    '''
    This searches the uninstall keys in the registry to find a match in the sub
    keys, it will return a dict with the display name as the key and the
    version as the value

    Args:

        include_components (bool):
            Include sub components of installed software. Default is ``True``

        include_updates (bool):
            Include software updates and Windows updates. Default is ``True``

    Returns:
        dict: A dictionary of installed software with versions installed

    .. code-block:: cfg

        {'<package_name>': '<version>'}
    '''
    # Logic for this can be found in this question:
    # https://social.technet.microsoft.com/Forums/windows/en-US/d913471a-d7fb-448d-869b-da9025dcc943/where-does-addremove-programs-get-its-information-from-in-the-registry
    # and also in the collectPlatformDependentApplicationData function in
    # https://github.com/aws/amazon-ssm-agent/blob/master/agent/plugins/inventory/gatherers/application/dataProvider_windows.go
    reg_software = {}

    def skip_component(hive, key, sub_key, use_32bit_registry):
        '''
        'SystemComponent' must be either absent or present with a value of 0,
        because this value is usually set on programs that have been installed
        via a Windows Installer Package (MSI).

        Returns:
            bool: True if the package needs to be skipped, otherwise False
        '''
        if include_components:
            return False
        if __utils__['reg.value_exists'](
                hive=hive,
                key='{0}\\{1}'.format(key, sub_key),
                vname='SystemComponent',
                use_32bit_registry=use_32bit_registry):
            if __utils__['reg.read_value'](
                    hive=hive,
                    key='{0}\\{1}'.format(key, sub_key),
                    vname='SystemComponent',
                    use_32bit_registry=use_32bit_registry)['vdata'] > 0:
                return True
        return False

    def skip_win_installer(hive, key, sub_key, use_32bit_registry):
        '''
        'WindowsInstaller' must be either absent or present with a value of 0.
        If the value is set to 1, then the application is included in the list
        if and only if the corresponding compressed guid is also present in
        HKLM:\\Software\\Classes\\Installer\\Products

        Returns:
            bool: True if the package needs to be skipped, otherwise False
        '''
        products_key = 'Software\\Classes\\Installer\\Products\\{0}'
        if __utils__['reg.value_exists'](
                hive=hive,
                key='{0}\\{1}'.format(key, sub_key),
                vname='WindowsInstaller',
                use_32bit_registry=use_32bit_registry):
            if __utils__['reg.read_value'](
                    hive=hive,
                    key='{0}\\{1}'.format(key, sub_key),
                    vname='WindowsInstaller',
                    use_32bit_registry=use_32bit_registry)['vdata'] > 0:
                squid = hubblestack.utils.win_functions.guid_to_squid(sub_key)
                if not __utils__['reg.key_exists'](
                        hive='HKLM',
                        key=products_key.format(squid),
                        use_32bit_registry=use_32bit_registry):
                    return True
        return False

    def skip_uninstall_string(hive, key, sub_key, use_32bit_registry):
        '''
        'UninstallString' must be present, because it stores the command line
        that gets executed by Add/Remove programs, when the user tries to
        uninstall a program.

        Returns:
            bool: True if the package needs to be skipped, otherwise False
        '''
        if not __utils__['reg.value_exists'](
                hive=hive,
                key='{0}\\{1}'.format(key, sub_key),
                vname='UninstallString',
                use_32bit_registry=use_32bit_registry):
            return True
        return False

    def skip_release_type(hive, key, sub_key, use_32bit_registry):
        '''
        'ReleaseType' must either be absent or if present must not have a
        value set to 'Security Update', 'Update Rollup', or 'Hotfix', because
        that indicates it's an update to an existing program.

        Returns:
            bool: True if the package needs to be skipped, otherwise False
        '''
        if include_updates:
            return False
        skip_types = ['Hotfix',
                      'Security Update',
                      'Update Rollup']
        if __utils__['reg.value_exists'](
                hive=hive,
                key='{0}\\{1}'.format(key, sub_key),
                vname='ReleaseType',
                use_32bit_registry=use_32bit_registry):
            if __utils__['reg.read_value'](
                    hive=hive,
                    key='{0}\\{1}'.format(key, sub_key),
                    vname='ReleaseType',
                    use_32bit_registry=use_32bit_registry)['vdata'] in skip_types:
                return True
        return False

    def skip_parent_key(hive, key, sub_key, use_32bit_registry):
        '''
        'ParentKeyName' must NOT be present, because that indicates it's an
        update to the parent program.

        Returns:
            bool: True if the package needs to be skipped, otherwise False
        '''
        if __utils__['reg.value_exists'](
                hive=hive,
                key='{0}\\{1}'.format(key, sub_key),
                vname='ParentKeyName',
                use_32bit_registry=use_32bit_registry):
            return True

        return False

    def add_software(hive, key, sub_key, use_32bit_registry):
        '''
        'DisplayName' must be present with a valid value, as this is reflected
        as the software name returned by pkg.list_pkgs. Also, its value must
        not start with 'KB' followed by 6 numbers - as that indicates a
        Windows update.
        '''
        d_name_regdata = __utils__['reg.read_value'](
            hive=hive,
            key='{0}\\{1}'.format(key, sub_key),
            vname='DisplayName',
            use_32bit_registry=use_32bit_registry)

        if (not d_name_regdata['success'] or
                d_name_regdata['vtype'] not in ['REG_SZ', 'REG_EXPAND_SZ'] or
                d_name_regdata['vdata'] in ['(value not set)', None, False]):
            return
        d_name = d_name_regdata['vdata']

        if not include_updates:
            if re.match(r'^KB[0-9]{6}', d_name):
                return

        d_vers_regdata = __utils__['reg.read_value'](
            hive=hive,
            key='{0}\\{1}'.format(key, sub_key),
            vname='DisplayVersion',
            use_32bit_registry=use_32bit_registry)

        d_vers = 'Not Found'
        if (d_vers_regdata['success'] and
                d_vers_regdata['vtype'] in ['REG_SZ', 'REG_EXPAND_SZ', 'REG_DWORD']):
            if isinstance(d_vers_regdata['vdata'], int):
                d_vers = str(d_vers_regdata['vdata'])
            elif d_vers_regdata['vdata'] and d_vers_regdata['vdata'] != '(value not set)':  # Check for blank values
                d_vers = d_vers_regdata['vdata']

        reg_software.setdefault(d_name, []).append(d_vers)

    # Start gathering information from the registry
    # HKLM Uninstall 64 bit
    kwargs = {'hive': 'HKLM',
              'key': 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
              'use_32bit_registry': False}
    for sub_key in __utils__['reg.list_keys'](**kwargs):
        kwargs['sub_key'] = sub_key
        if skip_component(**kwargs):
            continue
        if skip_win_installer(**kwargs):
            continue
        if skip_uninstall_string(**kwargs):
            continue
        if skip_release_type(**kwargs):
            continue
        if skip_parent_key(**kwargs):
            continue
        add_software(**kwargs)

    # HKLM Uninstall 32 bit
    kwargs['use_32bit_registry'] = True
    kwargs.pop('sub_key', False)
    for sub_key in __utils__['reg.list_keys'](**kwargs):
        kwargs['sub_key'] = sub_key
        if skip_component(**kwargs):
            continue
        if skip_win_installer(**kwargs):
            continue
        if skip_uninstall_string(**kwargs):
            continue
        if skip_release_type(**kwargs):
            continue
        if skip_parent_key(**kwargs):
            continue
        add_software(**kwargs)

    # HKLM Uninstall 64 bit
    kwargs = {'hive': 'HKLM',
              'key': 'Software\\Classes\\Installer\\Products',
              'use_32bit_registry': False}
    userdata_key = 'Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\' \
                   'UserData\\S-1-5-18\\Products'
    for sub_key in __utils__['reg.list_keys'](**kwargs):
        # If the key does not exist in userdata, skip it
        if not __utils__['reg.key_exists'](
                hive=kwargs['hive'],
                key='{0}\\{1}'.format(userdata_key, sub_key)):
            continue
        kwargs['sub_key'] = sub_key
        if skip_component(**kwargs):
            continue
        if skip_win_installer(**kwargs):
            continue
        add_software(**kwargs)

    # Uninstall for each user on the system (HKU), 64 bit
    # This has a propensity to take a while on a machine where many users have
    # logged in. Untested in such a scenario
    hive_hku = 'HKU'
    uninstall_key = '{0}\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
    product_key = '{0}\\Software\\Microsoft\\Installer\\Products'
    user_data_key = 'Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\' \
                    'UserData\\{0}\\Products\\{1}'
    for user_guid in __utils__['reg.list_keys'](hive=hive_hku):
        kwargs = {'hive': hive_hku,
                  'key': uninstall_key.format(user_guid),
                  'use_32bit_registry': False}
        if __utils__['reg.key_exists'](**kwargs):
            for sub_key in __utils__['reg.list_keys'](**kwargs):
                kwargs['sub_key'] = sub_key

                if skip_component(**kwargs):
                    continue
                if skip_win_installer(**kwargs):
                    continue
                if skip_uninstall_string(**kwargs):
                    continue
                if skip_release_type(**kwargs):
                    continue
                if skip_parent_key(**kwargs):
                    continue
                add_software(**kwargs)
        # While we have the user guid, we're gong to check userdata in HKLM
        kwargs = {'hive': hive_hku,
                'key': product_key.format(user_guid),
                'use_32bit_registry': False}
        if __utils__['reg.key_exists'](**kwargs):
            for sub_key in __utils__['reg.list_keys'](**kwargs):
                kwargs = {'hive': 'HKLM',
                            'key': user_data_key.format(user_guid, sub_key),
                            'use_32bit_registry': False}
                if __utils__['reg.key_exists'](**kwargs):
                    kwargs['sub_key'] = 'InstallProperties'
                    if skip_component(**kwargs):
                        continue
                    add_software(**kwargs)

    # Uninstall for each user on the system (HKU), 32 bit
    for user_guid in __utils__['reg.list_keys'](hive=hive_hku,
                                                use_32bit_registry=True):
        kwargs = {'hive': hive_hku,
                  'key': uninstall_key.format(user_guid),
                  'use_32bit_registry': True}
        if __utils__['reg.key_exists'](**kwargs):
            for sub_key in __utils__['reg.list_keys'](**kwargs):
                kwargs['sub_key'] = sub_key
                if skip_component(**kwargs):
                    continue
                if skip_win_installer(**kwargs):
                    continue
                if skip_uninstall_string(**kwargs):
                    continue
                if skip_release_type(**kwargs):
                    continue
                if skip_parent_key(**kwargs):
                    continue
                add_software(**kwargs)

        kwargs = {'hive': hive_hku,
                  'key': product_key.format(user_guid),
                  'use_32bit_registry': True}
        if __utils__['reg.key_exists'](**kwargs):
            # While we have the user guid, we're going to check userdata in HKLM
            for sub_key_2 in __utils__['reg.list_keys'](**kwargs):
                kwargs = {'hive': 'HKLM',
                          'key': user_data_key.format(user_guid, sub_key_2),
                          'use_32bit_registry': True}
                if __utils__['reg.key_exists'](**kwargs):
                    kwargs['sub_key'] = 'InstallProperties'
                    if skip_component(**kwargs):
                        continue
                    add_software(**kwargs)

    return reg_software

def _get_package_info(name, saltenv='base'):
    '''
    Return package info. Returns empty map if package not available
    TODO: Add option for version
    '''
    return get_repo_data(saltenv).get('repo', {}).get(name, {})

