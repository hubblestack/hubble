# -*- encoding: utf-8 -*-
"""
Loader and primary interface for nova modules

See README for documentation

Configuration:
    - hubblestack:nova:module_dir
    - hubblestack:nova:profile_dir
    - hubblestack:nova:saltenv
    - hubblestack:nova:autoload
    - hubblestack:nova:autosync
"""


import logging
import os
import traceback
import yaml

from salt.exceptions import CommandExecutionError
from hubblestack import __version__
from hubblestack.status import HubbleStatus

log = logging.getLogger(__name__)

hubble_status = HubbleStatus(__name__, 'top', 'audit')

try:
    from nova_loader import NovaLazyLoader
except ImportError:
    pass  # This is here to make the sphinx import of this module work

__nova__ = {}


@hubble_status.watch
def audit(configs=None,
          tags='*',
          verbose=None,
          show_success=None,
          show_compliance=None,
          show_profile=None,
          called_from_top=None,
          debug=None,
          labels=None,
          **kwargs):
    """
    Primary entry point for audit calls.

    configs
        List (comma-separated or python list) of yaml configs/directories to
        search for audit data. Directories are dot-separated, much in the same
        way as Salt states. For individual config names, leave the .yaml
        extension off.  If a given path resolves to a python file, it will be
        treated as a single config. Otherwise it will be treated as a
        directory. All configs found in a recursive search of the specified
        directories will be included in the audit.

        If configs is not provided, this function will call ``hubble.top``
        instead.

    tags
        Glob pattern string for tags to include in the audit. This way you can
        give a directory, and tell the system to only run the `CIS*`-tagged
        audits, for example.

    verbose
        Whether to show additional information about audits, including
        description, remediation instructions, etc. The data returned depends
        on the audit module. Defaults to False. Configurable via
        `hubblestack:nova:verbose` in minion config/pillar.

    show_success
        Whether to show successful audits in addition to failed audits.
        Defaults to True. Configurable via `hubblestack:nova:show_success` in
        minion config/pillar.

    show_compliance
        Whether to show compliance as a percentage (successful checks divided
        by total checks). Defaults to True. Configurable via
        `hubblestack:nova:show_compliance` in minion config/pillar.

    show_profile
        DEPRECATED

    called_from_top
        Ignore this argument. It is used for distinguishing between user-calls
        of this function and calls from hubble.top.

    debug
        Whether to log additional information to help debug nova. Defaults to
        False. Configurable via `hubblestack:nova:debug` in minion
        config/pillar.

    labels
        Tests with matching labels are executed. If multiple labels are passed,
        then tests which have all those labels are executed.

    **kwargs
        Any parameters & values that are not explicitly defined will be passed
        directly through to the Nova module(s).

    CLI Examples::

        salt '*' hubble.audit foo
        salt '*' hubble.audit foo,bar tags='CIS*'
        salt '*' hubble.audit foo,bar.baz verbose=True
    """
    if configs is None:
        return top(verbose=verbose,
                   show_success=show_success,
                   show_compliance=show_compliance,
                   labels=labels)
    if labels:
        if not isinstance(labels, list):
            labels = labels.split(',')
    if not called_from_top and __salt__['config.get']('hubblestack:nova:autoload', True):
        load()
    if not __nova__:
        return False, 'No nova modules/data have been loaded.'

    if verbose is None:
        verbose = __salt__['config.get']('hubblestack:nova:verbose', False)
    if show_success is None:
        show_success = __salt__['config.get']('hubblestack:nova:show_success', True)
    if show_compliance is None:
        show_compliance = __salt__['config.get']('hubblestack:nova:show_compliance', True)
    if show_profile is not None:
        log.warning(
            'Keyword argument \'show_profile\' is no longer supported'
        )
    if debug is None:
        debug = __salt__['config.get']('hubblestack:nova:debug', False)

    if not isinstance(configs, list):
        # Convert string
        configs = configs.split(',')

    # Convert config list to paths, with leading slashes
    configs = [os.path.join(os.path.sep, os.path.join(*(con.split('.yaml')[0]).split('.')))
               for con in configs]

    # Pass any module parameters through to the Nova module
    nova_kwargs = _get_nova_kwargs(**kwargs)

    log.debug('nova_kwargs: %s', str(nova_kwargs))

    ret = _run_audit(configs, tags, debug, labels, **nova_kwargs)
    results = _build_results(verbose, ret, show_success, show_compliance, called_from_top)

    return results


def _build_results(verbose, ret, show_success, show_compliance, called_from_top):
    """
    Helper function that builds the results to be returned depending
    on whether it was called with verbose or not.
    """
    terse_results, compliance = _build_terse_results(ret, show_success, show_compliance)

    # Format verbose output as single-key dictionaries with tag as key
    if verbose:
        results = _build_verbose_results(ret, show_success)
    else:
        results = terse_results

    if compliance:
        results['Compliance'] = compliance

    if not called_from_top and not results:
        results['Messages'] = 'No audits matched this host in the specified profiles.'

    for error in ret.get('Errors', []):
        if 'Errors' not in results:
            results['Errors'] = []
        results['Errors'].append(error)

    return results


def _get_nova_kwargs(**kwargs):
    """
    Helper function that builds the parameters to be passed to
    the Nova module in the form of kwargs.
    """
    nova_kwargs = {}
    # Get values from config first (if any) and merge into nova_kwargs
    nova_kwargs_config = __salt__['config.get']('hubblestack:nova:nova_kwargs', False)
    if nova_kwargs_config is not False:
        nova_kwargs.update(nova_kwargs_config)
    # Now process arguments from CLI and merge into nova_kwargs_dict
    if kwargs is not None:
        nova_kwargs.update(kwargs)

    return nova_kwargs


def _build_terse_results(ret, show_success, show_compliance):
    """
    Helper function that builds the results to be returned when the verbose parameter is not set
    """
    terse_results = {'Failure': []}

    # Pull out just the tag and description
    tags_descriptions = set()

    for tag_data in ret.get('Failure', []):
        tag = tag_data['tag']
        description = tag_data.get('description')
        if (tag, description) not in tags_descriptions:
            terse_results['Failure'].append({tag: description})
            tags_descriptions.add((tag, description))

    terse_results['Success'] = []
    tags_descriptions = set()

    for tag_data in ret.get('Success', []):
        tag = tag_data['tag']
        description = tag_data.get('description')
        if (tag, description) not in tags_descriptions:
            terse_results['Success'].append({tag: description})
            tags_descriptions.add((tag, description))

    terse_results['Controlled'] = []
    control_reasons = set()

    for tag_data in ret.get('Controlled', []):
        tag = tag_data['tag']
        control_reason = tag_data.get('control', '')
        description = tag_data.get('description')
        if (tag, description, control_reason) not in control_reasons:
            terse_results['Controlled'].append({tag: control_reason})
            control_reasons.add((tag, description, control_reason))

    # Calculate compliance level
    if show_compliance:
        compliance = _calculate_compliance(terse_results)
    else:
        compliance = False

    if not show_success and 'Success' in terse_results:
        terse_results.pop('Success')

    if not terse_results['Controlled']:
        terse_results.pop('Controlled')

    return terse_results, compliance


def _build_verbose_results(ret, show_success):
    """
    Helper function that builds the results to be returned when the verbose parameter is set
    """
    verbose_results = {'Failure': []}

    for tag_data in ret.get('Failure', []):
        tag = tag_data['tag']
        verbose_results['Failure'].append({tag: tag_data})

    verbose_results['Success'] = []

    for tag_data in ret.get('Success', []):
        tag = tag_data['tag']
        verbose_results['Success'].append({tag: tag_data})

    if not show_success and 'Success' in verbose_results:
        verbose_results.pop('Success')

    verbose_results['Controlled'] = []

    for tag_data in ret.get('Controlled', []):
        tag = tag_data['tag']
        verbose_results['Controlled'].append({tag: tag_data})

    if not verbose_results['Controlled']:
        verbose_results.pop('Controlled')

    return verbose_results


def _run_audit(configs, tags, debug, labels, **kwargs):
    """
    Function that runs the audits that need to be run based on the configs.
    """
    results = {}

    # compile list of tuples with profile name and profile data
    data_list = _build_audit_data(configs, results)

    if debug:
        log.debug('hubble.py configs:')
        log.debug(configs)
        log.debug('hubble.py data_list:')
        log.debug(data_list)
    # Run the audits
    # This is currently pretty brute-force -- we just run all the modules we
    # have available with the data list, so data will be processed multiple
    # times. However, for the scale we're working at this should be fine.
    # We can revisit if this ever becomes a big bottleneck
    for key, func in __nova__._dict.items():
        try:
            ret = func(data_list, tags, labels, **kwargs)
        except Exception:
            log.error('Exception occurred in nova module:')
            log.error(traceback.format_exc())
            if 'Errors' not in results:
                results['Errors'] = []
            results['Errors'].append({key: {'error': 'exception occurred',
                                            'data': traceback.format_exc().splitlines()[-1]}})
            continue
        else:
            if not isinstance(ret, dict):
                if 'Errors' not in results:
                    results['Errors'] = []
                results['Errors'].append({key: {'error': 'bad return type',
                                                'data': ret}})
                continue

        # Merge in the results
        for ret_key, ret_val in ret.items():
            if ret_key not in results:
                results[ret_key] = []
            results[ret_key].extend(ret_val)

    # Inspect the data for compensating control data
    processed_controls = _build_processed_controls(data_list, debug)

    # Look through the failed results to find audits which match our control config
    failures_to_remove = _build_failures_to_remove(results, processed_controls)

    # Remove controlled failures from results['Failure']
    for failure_index in reversed(sorted(set(failures_to_remove))):
        results['Failure'].pop(failure_index)

    for key in list(results.keys()):
        if not results[key]:
            results.pop(key)

    return results


def _build_audit_data(configs, results):
    """
    Helper function that goes over each config and extract the audit data sets
    that need to be run.
    """
    to_run = set()
    for config in configs:
        found_for_config = False
        for key in __nova__.__data__:
            key_path_split = key.split('.yaml')[0].split(os.path.sep)
            matches = True
            if config != os.path.sep:
                for i, path in enumerate(config.split(os.path.sep)):
                    if i >= len(key_path_split) or path != key_path_split[i]:
                        matches = False
            if matches:
                # Found a match, add the audit data to the set
                found_for_config = True
                to_run.add(key)
        if not found_for_config:
            # No matches were found for this entry, add an error
            if 'Errors' not in results:
                results['Errors'] = []
            results['Errors'].append(
                {config: {'error': 'No matching profiles found for {0}'.format(config)}})

    return [(key.split('.yaml')[0].split(os.path.sep)[-1],
             __nova__.__data__[key]) for key in to_run]


def _build_processed_controls(data_list, debug):
    """
    Helper function that builds a dictionary containing compensating control data
    """
    processed_controls = {}
    for _, audit_data in data_list:
        control_config = audit_data.get('control', [])
        for control in control_config:
            if isinstance(control, str):
                processed_controls[control] = {}
            else:  # dict
                for control_tag, control_data in control.items():
                    if isinstance(control_data, str):
                        processed_controls[control_tag] = {'reason': control_data}
                    else:  # dict
                        processed_controls[control_tag] = control_data
    if debug:
        log.debug('hubble.py control data:')
        log.debug(processed_controls)

    return processed_controls


def _build_failures_to_remove(results, processed_controls):
    """
    Helper function that goes over failed audits and looks for ones that
    match the control config.
    """
    failures_to_remove = []
    for i, failure in enumerate(results.get('Failure', [])):
        failure_tag = failure['tag']
        if failure_tag in processed_controls:
            failures_to_remove.append(i)
            if 'Controlled' not in results:
                results['Controlled'] = []
            failure.update({
                'control': processed_controls[failure_tag].get('reason')
            })
            results['Controlled'].append(failure)

    return failures_to_remove


@hubble_status.watch
def top(topfile='top.nova',
        verbose=None,
        show_success=None,
        show_compliance=None,
        show_profile=None,
        labels=None):
    """
    Compile and run all yaml data from the specified nova topfile.

    Nova topfiles look very similar to saltstack topfiles, except the top-level
    key is always ``nova``, as nova doesn't have a concept of environments.

    .. code-block:: yaml

        nova:
          '*':
            - cve_scan
            - cis_gen
          'web*':
            - firewall
            - cis-centos-7-l2-scored
            - cis-centos-7-apache24-l1-scored
          'G@os_family:debian':
            - netstat
            - cis-debian-7-l2-scored: 'CIS*'
            - cis-debian-7-mysql57-l1-scored: 'CIS 2.1.2'

    Additionally, all nova topfile matches are compound matches, so you never
    need to define a match type like you do in saltstack topfiles.

    Each list item is a string representing the dot-separated location of a
    yaml file which will be run with hubble.audit. You can also specify a
    tag glob to use as a filter for just that yaml file, using a colon
    after the yaml file (turning it into a dictionary). See the last two lines
    in the yaml above for examples.


    Arguments:

    topfile
        The path of the topfile, relative to your hubblestack_nova_profiles
        directory.

    verbose
        Whether to show additional information about audits, including
        description, remediation instructions, etc. The data returned depends
        on the audit module. Defaults to False. Configurable via
        `hubblestack:nova:verbose` in minion config/pillar.

    show_success
        Whether to show successful audits in addition to failed audits.
        Defaults to True. Configurable via `hubblestack:nova:show_success` in
        minion config/pillar.

    show_compliance
        Whether to show compliance as a percentage (successful checks divided
        by total checks). Defaults to True. Configurable via
        `hubblestack:nova:show_compliance` in minion config/pillar.

    show_profile
        DEPRECATED

    debug
        Whether to log additional information to help debug nova. Defaults to
        False. Configurable via `hubblestack:nova:debug` in minion
        config/pillar.

    CLI Examples:

    .. code-block:: bash

        salt '*' hubble.top
        salt '*' hubble.top foo/bar/top.nova
        salt '*' hubble.top foo/bar.nova verbose=True
    """
    if __salt__['config.get']('hubblestack:nova:autoload', True):
        load()
    if not __nova__:
        return False, 'No nova modules/data have been loaded.'

    if verbose is None:
        verbose = __salt__['config.get']('hubblestack:nova:verbose', False)
    if show_success is None:
        show_success = __salt__['config.get']('hubblestack:nova:show_success', True)
    if show_compliance is None:
        show_compliance = __salt__['config.get']('hubblestack:nova:show_compliance', True)
    if show_profile is not None:
        log.warning(
            'Keyword argument \'show_profile\' is no longer supported'
        )

    results = {}

    # Will be a combination of strings and single-item dicts. The strings
    # have no tag filters, so we'll treat them as tag filter '*'. If we sort
    # all the data by tag filter we can batch where possible under the same
    # tag.
    data_by_tag = _build_data_by_tag(topfile, results)

    if not data_by_tag:
        return results

    # Run the audits
    for tag, data in data_by_tag.items():
        ret = audit(configs=data,
                    tags=tag,
                    verbose=verbose,
                    show_success=True,
                    show_compliance=False,
                    called_from_top=True,
                    labels=labels)

        # Merge in the results
        for key, val in ret.items():
            if key not in results:
                results[key] = []
            results[key].extend(val)

    if show_compliance:
        compliance = _calculate_compliance(results)
        if compliance:
            results['Compliance'] = compliance

    _clean_up_results(results, show_success)

    return results


def _build_data_by_tag(topfile, results):
    """
    Helper function that goes over data in top_data and
    aggregate it by tag
    """
    data_by_tag = {}

    # Get a list of yaml to run
    top_data = _get_top_data(topfile)

    for data in top_data:
        if isinstance(data, str):
            if '*' not in data_by_tag:
                data_by_tag['*'] = []
            data_by_tag['*'].append(data)
        elif isinstance(data, dict):
            for key, tag in data.items():
                if tag not in data_by_tag:
                    data_by_tag[tag] = []
                data_by_tag[tag].append(key)
        else:
            if 'Errors' not in results:
                results['Errors'] = {}
            error_log = 'topfile malformed, list entries must be strings or ' \
                        'dicts: {0} | {1}'.format(data, type(data))
            results['Errors'][topfile] = {'error': error_log}
            log.error(error_log)
            continue

    return data_by_tag


def _clean_up_results(results, show_success):
    """
    Helper function that cleans up the results by
    removing the keys with empty values, removing `success`
    if show_success was not passed, adding an error message if
    results is empty
    """
    for key in list(results.keys()):
        if not results[key]:
            results.pop(key)

    if not results:
        results['Messages'] = 'No audits matched this host in the specified profiles.'

    if not show_success and 'Success' in results:
        results.pop('Success')


def sync(clean=False):
    """
    Sync the nova audit modules and profiles from the saltstack fileserver.

    The modules should be stored in the salt fileserver. By default nova will
    search the base environment for a top level ``hubblestack_nova``
    directory, unless otherwise specified via pillar or minion config
    (``hubblestack:nova:module_dir``)

    The profiles should be stored in the salt fileserver. By default nova will
    search the base environment for a top level ``hubblestack_nova_profiles``
    directory, unless otherwise specified via pillar or minion config
    (``hubblestack:nova:profile_dir``)

    Modules and profiles will be cached in the normal minion cachedir

    Returns a boolean representing success

    NOTE: This function will optionally clean out existing files at the cached
    location, as cp.cache_dir doesn't clean out old files. Pass ``clean=True``
    to enable this behavior

    CLI Examples:

    .. code-block:: bash

        salt '*' nova.sync
        salt '*' nova.sync saltenv=hubble
    """
    log.debug('syncing nova modules')
    nova_profile_dir = __salt__['config.get']('hubblestack:nova:profile_dir',
                                              'salt://hubblestack_nova_profiles')
    _nova_module_dir, cached_profile_dir = _hubble_dir()
    saltenv = __salt__['config.get']('hubblestack:nova:saltenv', 'base')

    # Clean previously synced files
    if clean:
        __salt__['file.remove'](cached_profile_dir)

    synced = []
    # Support optional salt:// in config
    if 'salt://' in nova_profile_dir:
        path = nova_profile_dir
        _, _, nova_profile_dir = nova_profile_dir.partition('salt://')
    else:
        path = 'salt://{0}'.format(nova_profile_dir)

    # Sync the files
    cached = __salt__['cp.cache_dir'](path, saltenv=saltenv)

    if cached and isinstance(cached, list):
        # Success! Trim the paths
        cachedir = os.path.dirname(cached_profile_dir)
        ret = [relative.partition(cachedir)[2] for relative in cached]
        synced.extend(ret)
    else:
        if isinstance(cached, list):
            # Nothing was found
            synced.extend(cached)
        else:
            # Something went wrong, there's likely a stacktrace in the output
            # of cache_dir
            raise CommandExecutionError('An error occurred while syncing: {0}'
                                        .format(cached))
    return synced


def load():
    """
    Load the synced audit modules.
    """
    if __salt__['config.get']('hubblestack:nova:autosync', True):
        sync()

    for nova_dir in _hubble_dir():
        if not os.path.isdir(nova_dir):
            return False, 'No synced nova modules/profiles found'

    log.debug('loading nova modules')

    global __nova__
    __nova__ = NovaLazyLoader(_hubble_dir(), __opts__, __grains__, __pillar__, __salt__)

    ret = {'loaded': list(__nova__._dict.keys()),
           'missing': __nova__.missing_modules,
           'data': list(__nova__.__data__.keys()),
           'missing_data': __nova__.__missing_data__}
    return ret


def version():
    """
    Report the version of this module
    """
    return __version__


def _hubble_dir():
    """
    Generate the local minion directories to which nova modules and profiles
    are synced

    Returns a tuple of two paths, the first for nova modules, the second for
    nova profiles
    """
    nova_profile_dir = __salt__['config.get']('hubblestack:nova:profile_dir',
                                              'salt://hubblestack_nova_profiles')
    nova_module_dir = os.path.join(__opts__['install_dir'], 'files', 'hubblestack_nova')
    # Support optional salt:// in config
    if 'salt://' in nova_profile_dir:
        _, _, nova_profile_dir = nova_profile_dir.partition('salt://')
    saltenv = __salt__['config.get']('hubblestack:nova:saltenv', 'base')
    cachedir = os.path.join(__opts__.get('cachedir'),
                            'files',
                            saltenv,
                            nova_profile_dir)
    dirs = [nova_module_dir, cachedir]
    return tuple(dirs)


def _calculate_compliance(results):
    """
    Calculate compliance numbers given the results of audits
    """
    success = len(results.get('Success', []))
    failure = len(results.get('Failure', []))
    control = len(results.get('Controlled', []))
    total_audits = success + failure + control

    if total_audits:
        compliance = float(success + control) / total_audits
        compliance = int(compliance * 100)
        compliance = '{0}%'.format(compliance)
        return compliance
    return None


def _get_top_data(topfile):
    """
    Helper method to retrieve and parse the nova topfile
    """
    topfile = os.path.join(_hubble_dir()[1], topfile)

    try:
        with open(topfile) as handle:
            topdata = yaml.safe_load(handle)
    except Exception as exc:
        raise CommandExecutionError('Could not load topfile: {0}'.format(exc))

    if not isinstance(topdata, dict) or 'nova' not in topdata or \
            (not isinstance(topdata['nova'], dict)):
        raise CommandExecutionError('Nova topfile not formatted correctly')

    topdata = topdata['nova']

    ret = []

    for match, data in topdata.items():
        if __salt__['match.compound'](match):
            ret.extend(data)

    return ret
