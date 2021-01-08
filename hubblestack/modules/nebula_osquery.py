# -*- coding: utf-8 -*-
"""
osquery wrapper for HubbleStack Nebula

Designed to run sets of osquery queries defined in pillar. These sets will have
a unique identifier, and be targeted by identifier. Usually, this identifier
will be a frequency. ('15 minutes', '1 day', etc). Identifiers are
case-insensitive.

You can then use the scheduler of your choice to run sets os queries at
whatever frequency you choose.

Sample pillar data:

nebula_osquery:
  hour:
    - crontab: query: select c.*,t.iso_8601 as _time from crontab as c join time as t;
    - query_name: suid_binaries
      query: select sb.*, t.iso_8601 as _time from suid_bin as sb join time as t;
  day:
    - query_name: rpm_packages
      query: select rpm.*, t.iso_8601 from rpm_packages as rpm join time as t;
"""


import collections
import copy
import fnmatch
import glob
import json
import logging
import os
import re
import shutil
import time
import hashlib
import yaml
import zlib
import traceback
from inspect import getfullargspec

import hubblestack.utils.files
import hubblestack.utils.platform

from hubblestack.exceptions import CommandExecutionError
from hubblestack import __version__
import hubblestack.log

from hubblestack.status import HubbleStatus
log = logging.getLogger(__name__)

CRC_BYTES = 256
hubble_status = HubbleStatus(__name__, 'top', 'queries', 'osqueryd_monitor', 'osqueryd_log_parser')

__virtualname__ = 'nebula'
__RESULT_LOG_OFFSET__ = {}
OSQUERYD_NEEDS_RESTART = False
isFipsEnabled = True if 'usedforsecurity' in getfullargspec(hashlib.new).kwonlyargs else False

def __virtual__():
    return __virtualname__


@hubble_status.watch
def queries(query_group,
            query_file=None,
            verbose=False,
            report_version_with_day=True,
            topfile_for_mask=None,
            mask_passwords=False):
    """
    Run the set of queries represented by ``query_group`` from the
    configuration in the file query_file

    query_group
        Group of queries to run

    query_file
        salt:// file which will be parsed for osquery queries

    verbose
        Defaults to False. If set to True, more information (such as the query
        which was run) will be included in the result.

    topfile_for_mask
        This is the location of the top file from which the masking information
        will be extracted.

    mask_passwords
        Defaults to False. If set to True, passwords mentioned in the
        return object are masked.

    CLI Examples:

    .. code-block:: bash

        salt '*' nebula.queries day
        salt '*' nebula.queries hour verbose=True
        salt '*' nebula.queries hour pillar_key=sec_osqueries
    """
    # sanity check of query_file: if not present, add it
    if hubblestack.utils.platform.is_windows():
        query_file = query_file or \
                     'salt://hubblestack_nebula_v2/hubblestack_nebula_win_queries.yaml'
    else:
        query_file = query_file or 'salt://hubblestack_nebula_v2/hubblestack_nebula_queries.yaml'
    if not isinstance(query_file, list):
        query_file = [query_file]

    query_data = _get_query_data(query_file)
    __opts__['nebula_queries'] = query_data

    if query_data is None or not query_group:
        return None

    if 'osquerybinpath' not in __grains__:
        if query_group == 'day':
            log.warning('osquery not installed on this host. Returning baseline data')
            return _build_baseline_osquery_data(report_version_with_day)
        log.debug('osquery not installed on this host. Skipping.')
        return None

    query_data = query_data.get(query_group, {})

    schedule_time = time.time()

    # run the osqueryi queries
    success, timing, ret = _run_osquery_queries(query_data, verbose)

    if success is False and hubblestack.utils.platform.is_windows():
        log.error('osquery does not run on windows versions earlier than Server 2008 and Windows 7')
        if query_group == 'day':
            ret = [
                {'fallback_osfinger': {
                    'data': [{'osfinger': __grains__.get('osfinger', __grains__.get('osfullname')),
                              'osrelease': __grains__.get('osrelease', __grains__.get(
                                  'lsb_distrib_release'))}],
                    'result': True}},
                {'fallback_error': {
                    'data': 'osqueryi is installed but not compatible with this version of windows',
                    'result': True}}]
            return ret
        return None

    if __mods__['config.get']('splunklogging', False):
        log.debug('Logging osquery timing data to splunk')
        timing_data = {'query_run_length': timing,
                       'schedule_time': schedule_time}
        hubblestack.log.emit_to_splunk(timing_data, 'INFO', 'hubblestack.osquery_timing')

    if query_group == 'day' and report_version_with_day:
        ret.append(hubble_versions())

    ret = _update_osquery_results(ret)

    if mask_passwords:
        _mask_object(ret, topfile_for_mask)

    return ret


def _build_baseline_osquery_data(report_version_with_day):
    """
    Build the baseline data to be returned if osquery is not installed on the host.
    """
    # Match the formatting of normal osquery results. Not super readable,
    # but just add new dictionaries to the list as we need more data
    ret = [{'fallback_osfinger': {
        'data': [{'osfinger': __grains__.get('osfinger', __grains__.get('osfullname')),
                  'osrelease': __grains__.get('osrelease', __grains__.get(
                      'lsb_distrib_release'))}],
        'result': True}}]
    if 'pkg.list_pkgs' in __mods__:
        ret.append(
            {'fallback_pkgs': {
                'data': [{'name': k, 'version': v}
                         for k, v in __mods__['pkg.list_pkgs']().items()],
                'result': True}})
    uptime = __mods__['status.uptime']()
    if isinstance(uptime, dict):
        uptime = uptime.get('seconds', __mods__['cmd.run']('uptime'))
    ret.append(
        {'fallback_uptime': {'data': [{'uptime': uptime}],
                             'result': True}})
    if report_version_with_day:
        ret.append(hubble_versions())

    return ret


def _run_osqueryi_query(query, query_sql, timing, verbose):
    """
    Run the osqueryi query in query_sql and return the result
    """
    max_file_size = 104857600
    augeas_lenses = '/opt/osquery/lenses'
    query_ret = {'result': True}

    # Run the osqueryi query
    cmd = [__grains__['osquerybinpath'], '--read_max', max_file_size, '--json',
          '--augeas_lenses', augeas_lenses, query_sql]

    time_start = time.time()
    res = __mods__['cmd.run_all'](cmd, timeout=600)
    time_end = time.time()
    timing[query['query_name']] = time_end - time_start
    if res['retcode'] == 0:
        query_ret['data'] = json.loads(res['stdout'])
    else:
        if 'Timed out' in res['stdout']:
            # this is really the best way to tell without getting fancy
            log.error('TIMEOUT during osqueryi execution name=%s', query['query_name'])
        query_ret['result'] = False
        query_ret['error'] = res['stderr']
    if verbose:
        tmp = copy.deepcopy(query)
        tmp['query_result'] = query_ret
    else:
        tmp = {query['query_name']: query_ret}

    return tmp


def _run_osquery_queries(query_data, verbose):
    """
    Go over the query data in the osquery query file, run each query
    and return the aggregated results.
    """
    ret = []
    timing = {}
    success = True
    for name, query in query_data.items():
        query['query_name'] = name
        query_sql = query.get('query')
        if not query_sql:
            continue
        if 'attach' in query_sql.lower() or 'curl' in query_sql.lower():
            log.critical('Skipping potentially malicious osquery query \'%s\' '
                         'which contains either \'attach\' or \'curl\': %s',
                         name, query_sql)
            continue

        # Run osquery query
        query_ret = _run_osqueryi_query(query, query_sql, timing, verbose)
        try:
            if query_ret['query_result']['result'] is False or \
               query_ret[name]['result'] is False:
                success = False
        except KeyError:
            pass
        ret.append(query_ret)

    return success, timing, ret


def _update_osquery_results(ret):
    """
    Go over the data in the results obtained by running osquery queries and update by JSONIFYing
    Returns the updated version.
    """
    for data in ret:
        for _query_name, query_ret in data.items():
            if 'data' not in query_ret:
                continue
            for result in query_ret['data']:
                for key, value in result.items():
                    if value and isinstance(value, str) and\
                            value.startswith('__JSONIFY__'):
                        result[key] = json.loads(value[len('__JSONIFY__'):])

    return ret


def _get_query_data(query_file):
    """
    Helper function that extracts the query data from the query file and returns it.
    """
    query_data = {}
    for file_path in query_file:
        if 'salt://' in file_path:
            orig_fh = file_path
            file_path = __mods__['cp.cache_file'](file_path)
        if not file_path:
            log.error('Could not find file %s.', orig_fh)
            return None
        if os.path.isfile(file_path):
            with open(file_path, 'r') as yaml_file:
                f_data = yaml.safe_load(yaml_file)
                if not isinstance(f_data, dict):
                    raise CommandExecutionError('File data is not formed as a dict {0}'
                                                .format(f_data))
                query_data = _dict_update(query_data,
                                          f_data,
                                          recursive_update=True,
                                          merge_lists=True)
    return query_data


@hubble_status.watch
def osqueryd_monitor(configfile=None,
                     conftopfile=None,
                     flagstopfile=None,
                     flagfile=None,
                     logdir=None,
                     databasepath=None,
                     pidfile=None,
                     hashfile=None):
    """
    This function will monitor whether osqueryd is running on the system or not.
    Whenever it detects that osqueryd is not running, it will start the osqueryd.
    Also, it checks for conditions that would require osqueryd to restart
    (such as changes in flag file content). On such conditions, osqueryd will get restarted,
    thereby loading new files.

    configfile
        Path to osquery configuration file. If this is specified, conftopfile will be ignored

    conftopfile
        Path to topfile which will be used to dynamically generate osquery conf in JSON format

    flagstopfile
        Path to topfile which will be used to dynamically generate osquery flags

    flagfile
        Path to osquery flag file. If this is specified, flagstopfile will be ignored

    logdir
        Path to log directory where osquery daemon/service will write logs

    pidfile
        pidfile path where osquery daemon will write pid info

    hashfile
        path to hashfile where osquery flagfile's hash would be stored

    daemonize
        daemonize osquery daemon. Default is True. Applicable for posix system only

    """
    log.info("Starting osqueryd monitor")
    saltenv = __mods__['config.get']('hubblestack:nova:saltenv', 'base')
    log.debug('Cached nebula files to cachedir')
    cachedir = os.path.join(__opts__.get('cachedir'), 'files', saltenv, 'hubblestack_nebula_v2')
    base_path = cachedir
    servicename = "hubble_osqueryd"
    # sanity check each file and if not present assign a new value
    logdir = logdir or __opts__.get('osquerylogpath')
    databasepath = databasepath or __opts__.get('osquery_dbpath')
    pidfile = pidfile or os.path.join(base_path, "hubble_osqueryd.pidfile")
    hashfile = hashfile or os.path.join(base_path, "hash_of_flagfile.txt")
    if hubblestack.utils.platform.is_windows():
        conftopfile = conftopfile or 'salt://hubblestack_nebula_v2/win_top.osqueryconf'
        flagstopfile = flagstopfile or 'salt://hubblestack_nebula_v2/win_top.osqueryflags'

        osqueryd_running = _osqueryd_running_status_windows(servicename)
    else:
        conftopfile = conftopfile or 'salt://hubblestack_nebula_v2/top.osqueryconf'
        flagstopfile = flagstopfile or 'salt://hubblestack_nebula_v2/top.osqueryflags'

        osqueryd_running = _osqueryd_running_status(pidfile)

    configfile = configfile or _generate_osquery_conf_file(conftopfile)
    flagfile = flagfile or _generate_osquery_flags_file(flagstopfile)
    if not osqueryd_running:
        _start_osqueryd(pidfile, configfile, flagfile, logdir, databasepath, servicename)
    else:
        osqueryd_restart = _osqueryd_restart_required(hashfile, flagfile)
        if osqueryd_restart:
            _restart_osqueryd(pidfile, configfile, flagfile, logdir,
                              databasepath, hashfile, servicename)


@hubble_status.watch
def osqueryd_log_parser(osqueryd_logdir=None,
                        backuplogdir=None,
                        maxlogfilesizethreshold=None,
                        logfilethresholdinbytes=None,
                        backuplogfilescount=None,
                        enablediskstatslogging=False,
                        topfile_for_mask=None,
                        mask_passwords=False):
    """
    Parse osquery daemon logs and perform log rotation based on specified parameters

    osqueryd_logdir
        Directory path where osquery result and snapshot logs would be created

    backuplogdir
        Directory path where hubble should create log file backups post log rotation

    maxlogfilesizethreshold
        Log file size threshold in bytes. If osquery log file size is greter than this value,
        then logs will only be roatated but not parsed

    logfilethresholdinbytes
        Log file size threshold in bytes. If osquery log file is greter than this value,
        then log rotation will be done once logs have been processed

    backuplogfilescount
        Number of log file backups to keep

    enablediskstatslogging
        Enable logging of disk usage of /var/log partition. Default is False

    topfile_for_mask
        This is the location of the top file from which the masking information
        will be extracted

    mask_passwords
        Defaults to False. If set to True, passwords mentioned in the
        return object are masked

    """
    ret = []
    if not osqueryd_logdir:
        osqueryd_logdir = __opts__.get('osquerylogpath')
    result_logfile = os.path.normpath(os.path.join(osqueryd_logdir, 'osqueryd.results.log'))
    snapshot_logfile = os.path.normpath(os.path.join(osqueryd_logdir, 'osqueryd.snapshots.log'))

    log.debug("Result log file resolved to: %s", result_logfile)
    log.debug("Snapshot log file resolved to: %s", snapshot_logfile)

    backuplogdir = backuplogdir or __opts__.get('osquerylog_backupdir')
    logfilethresholdinbytes = logfilethresholdinbytes or __opts__.get('osquery_logfile_maxbytes')
    maxlogfilesizethreshold = maxlogfilesizethreshold or __opts__.get(
        'osquery_logfile_maxbytes_toparse')
    backuplogfilescount = backuplogfilescount or __opts__.get('osquery_backuplogs_count')

    if os.path.exists(result_logfile):
        logfile_offset = _get_file_offset(result_logfile)
        event_data = _parse_log(result_logfile,
                                logfile_offset,
                                backuplogdir,
                                logfilethresholdinbytes,
                                maxlogfilesizethreshold,
                                backuplogfilescount,
                                enablediskstatslogging)
        if event_data:
            ret += event_data
    else:
        log.warn("Specified osquery result log file doesn't exist: %s", result_logfile)

    if os.path.exists(snapshot_logfile):
        logfile_offset = _get_file_offset(snapshot_logfile)
        event_data = _parse_log(snapshot_logfile,
                                logfile_offset,
                                backuplogdir,
                                logfilethresholdinbytes,
                                maxlogfilesizethreshold,
                                backuplogfilescount,
                                enablediskstatslogging)
        if event_data:
            ret += event_data
    else:
        log.warn("Specified osquery snapshot log file doesn't exist: %s", snapshot_logfile)

    ret = _update_event_data(ret)

    if mask_passwords:
        log.info("Perform masking")
        _mask_object(ret, topfile_for_mask)
    return ret


def _update_event_data(ret):
    """
    Helper function that goes over the event_data in ret and updates the objects with 'snapshot and
    'column' action that have __JSONIFY__.
    Returns the updated ret.
    """
    # sanity check
    if not ret:
        return ret

    n_ret = []
    for event_data in ret:
        obj = json.loads(event_data)
        if 'action' in obj and obj['action'] == 'snapshot':
            for result in obj['snapshot']:
                for key, value in result.items():
                    if value and isinstance(value, str) and \
                            value.startswith('__JSONIFY__'):
                        result[key] = json.loads(value[len('__JSONIFY__'):])
        elif 'action' in obj:
            for key, value in obj['columns'].items():
                if value and isinstance(value, str) and value.startswith('__JSONIFY__'):
                    obj['columns'][key] = json.loads(value[len('__JSONIFY__'):])
        n_ret.append(obj)

    return n_ret


def check_disk_usage(path=None):
    """
    Check disk usage of specified path.
    If no path is specified, path will default to '/var/log'

    Can be scheduled via hubble conf as well

    *** Linux Only method ***

    path
        Defaults to '/var/log'

    """
    disk_stats = {}
    if hubblestack.utils.platform.is_windows():
        log.info("Platform is windows, skipping disk usage stats")
        disk_stats = {"Error": "Platform is windows"}
    else:
        if not path:
            # We would be interested in var partition disk stats only,
            # for other partitions specify 'path' param
            path = "/var/log"
        df_stat = os.statvfs(path)
        total = df_stat.f_frsize * df_stat.f_blocks
        avail = df_stat.f_frsize * df_stat.f_bavail
        used = total - avail
        per_used = float(used) / total * 100
        log.info("Stats for path: %s, Total: %f, Available: %f, Used: %f, Used %%: %f", path,
                 total, avail, used, per_used)
        disk_stats = {'total': total,
                      'available': avail,
                      'used': used,
                      'use_percent': per_used,
                      'path': path}

        if __mods__['config.get']('splunklogging', False):
            log.debug('Logging disk usage stats to splunk')
            stats = {'disk_stats': disk_stats, 'schedule_time': time.time()}
            hubblestack.log.emit_to_splunk(stats, 'INFO', 'hubblestack.disk_usage')

    return disk_stats


def fields(*args):
    """
    Use config.get to retrieve custom data based on the keys in the `*args`
    list.

    Arguments:

    *args
        List of keys to retrieve
    """
    ret = {}
    for field in args:
        ret['custom_{0}'.format(field)] = __mods__['config.get'](field)
    # Return it as nebula data
    if ret:
        return [{'custom_fields': {
            'data': [ret],
            'result': True
        }}]
    return []


def version():
    """
    Report version of this module
    """
    return __version__


def hubble_versions():
    """
    Report version of all hubble modules as query
    """
    versions = {'nova': __version__,
                'nebula': __version__,
                'pulsar': __version__,
                'quasar': __version__}

    return {'hubble_versions': {'data': [versions],
                                'result': True}}


@hubble_status.watch
def top(query_group,
        topfile='salt://hubblestack_nebula_v2/top.nebula',
        topfile_for_mask=None,
        mask_passwords=False):
    """
    Run the queries represented by query_group from the configuration files extracted from topfile
    """
    if hubblestack.utils.platform.is_windows():
        topfile = 'salt://hubblestack_nebula_v2/win_top.nebula'

    configs = _get_top_data(topfile)

    configs = ['salt://hubblestack_nebula_v2/' + config.replace('.', '/') + '.yaml'
               for config in configs]

    return queries(query_group,
                   query_file=configs,
                   verbose=False,
                   report_version_with_day=True,
                   topfile_for_mask=topfile_for_mask,
                   mask_passwords=mask_passwords)


def _get_top_data(topfile):
    """
    Function that reads the topfile and returns a list of matched configs that
    represent .yaml config files
    """
    topfile = __mods__['cp.cache_file'](topfile)

    if not topfile:
        raise CommandExecutionError('Topfile not found.')

    try:
        with open(topfile) as handle:
            topdata = yaml.safe_load(handle)
    except Exception as exc:
        raise CommandExecutionError('Could not load topfile: {0}'.format(exc))

    if not isinstance(topdata, dict) or 'nebula' not in topdata or \
            not isinstance(topdata['nebula'], list):
        raise CommandExecutionError('Nebula topfile not formatted correctly. '
                                    'Note that under the "nebula" key the data should now be'
                                    ' formatted as a list of single-key dicts.')

    topdata = topdata['nebula']

    ret = []

    for topmatch in topdata:
        for match, data in topmatch.items():
            if __mods__['match.compound'](match):
                ret.extend(data)

    return ret


def _generate_osquery_conf_file(conftopfile):
    """
    Function to dynamically create osquery configuration file in JSON format.
    This function would load osquery configuration in YAML format and
    make use of topfile to selectively load file(s) based on grains
    """

    log.info("Generating osquery conf file using topfile: %s", conftopfile)
    saltenv = __mods__['config.get']('hubblestack:nova:saltenv', 'base')
    log.debug('Cached nebula files to cachedir')
    cachedir = os.path.join(__opts__.get('cachedir'), 'files', saltenv, 'hubblestack_nebula_v2')
    base_path = cachedir

    osqd_configs = _get_top_data(conftopfile)
    configfile = os.path.join(base_path, "osquery.conf")
    conf_data = {}
    osqd_configs = ['salt://hubblestack_nebula_v2/' + config.replace('.', '/') + '.yaml'
                    for config in osqd_configs]
    for osqd_conf in osqd_configs:
        if 'salt://' in osqd_conf:
            orig_fh = osqd_conf
            osqd_conf = __mods__['cp.cache_file'](osqd_conf)
        if not osqd_conf:
            log.error('Could not find file %s.', orig_fh)
            return None
        if os.path.isfile(osqd_conf):
            with open(osqd_conf, 'r') as yfile:
                f_data = yaml.safe_load(yfile)
                if not isinstance(f_data, dict):
                    raise CommandExecutionError('File data is not formed as a dict {0}'
                                                .format(f_data))
                conf_data = _dict_update(conf_data,
                                         f_data,
                                         recursive_update=True,
                                         merge_lists=True)
    if conf_data:
        try:
            log.debug("Writing config to osquery.conf file")
            with open(configfile, "w") as conf_file:
                json.dump(conf_data, conf_file)
        except Exception:
            log.error("Failed to generate osquery conf file using topfile.", exc_info=True)

    return configfile


def _generate_osquery_flags_file(flagstopfile):
    """
    Function to dynamically create osquery flags file.
    This function would load osquery flags in YAML format and
    make use of topfile to selectively load file(s) based on grains
    """

    log.info("Generating osquery flags file using topfile: %s", flagstopfile)
    saltenv = __mods__['config.get']('hubblestack:nova:saltenv', 'base')
    log.debug('Cached nebula files to cachedir')
    cachedir = os.path.join(__opts__.get('cachedir'), 'files', saltenv, 'hubblestack_nebula_v2')
    base_path = cachedir

    osqd_flags = _get_top_data(flagstopfile)
    flagfile = os.path.join(base_path, "osquery.flags")
    flags_data = {}
    osqd_flags = ['salt://hubblestack_nebula_v2/' + config.replace('.', '/') + '.yaml'
                  for config in osqd_flags]
    for out_file in osqd_flags:
        if 'salt://' in out_file:
            orig_fh = out_file
            out_file = __mods__['cp.cache_file'](out_file)
        if not out_file:
            log.error('Could not find file %s.', orig_fh)
            return None
        if os.path.isfile(out_file):
            with open(out_file, 'r') as yfile:
                f_data = yaml.safe_load(yfile)
                if not isinstance(f_data, dict):
                    raise CommandExecutionError('File data is not formed as a dict {0}'
                                                .format(f_data))
                flags_data = _dict_update(flags_data,
                                          f_data,
                                          recursive_update=True,
                                          merge_lists=True)
    if flags_data:
        try:
            log.debug("Writing config to osquery.flags file")
            with open(flagfile, "w") as prop_file:
                for key in flags_data:
                    propdata = "--" + key + "=" + flags_data.get(key) + "\n"
                    prop_file.write(propdata)
        except Exception:
            log.error("Failed to generate osquery flags file using topfile.", exc_info=True)

    return flagfile


def _mask_object(object_to_be_masked, topfile):
    """
    Given an object with potential secrets (or other data that should not be
    returned), mask the contents of that object as configured in the mask
    configuration file. The mask configuration file used is defined by the
    top data in the ``topfile`` argument.

    If multiple mask.yaml files are matched in the topfile, the data within
    them will be recursively merged.

    If no matching mask_files are found in the top.mask file, no masking will
    happen.

    Note that this function has side effects: alterations to
    ``object_to_be_masked`` will be made in place.

    Sample mask.yaml data (with inline documentation):

    .. code-block:: yaml

        # Pattern that will replace whatever is masked
        mask_with: '***masked*by*hubble***'

        # Target and mask strings based on regex patterns
        # Can limit search specific queries and columns

        # Some osquery results are formed as lists of dicts. We can mask
        # based on variable names within these dicts.
        blacklisted_objects:

            - query_names:
              - 'running_procs'
              - 'listening_procs'          # List of name(s) of the osquery to be masked.
                                           # Put '*' to match all queries. Note
                                           # that query_names doesn't support
                                           # full globbing. '*' is just given
                                           # special treatment.
              column: 'environment'  # Column name in the osquery to be masked.
                                       No regex or glob support
              custom_mask_column: 'environment'  # Column name which stores environment variables
              custom_mask_key: '__hubble_mask__' # Env variable to look for constructing custom
                                                   blacklist of patterns
              attribute_to_check: 'variable_name' # Optional attribute
                                                  # In the inner dict, this is the key
                                                  # to check for blacklisted_patterns
                                                  # Will skipped if column specified is of
                                                    type 'String'
              attributes_to_mask: # Optional attribute, Values under these keys in the dict will be
                - 'value'  # masked, assuming one of the blacklisted_patterns
                           # is found under attribute_to_check in the same dict
                           # Will be skipped if column specified is of type 'String'
              blacklisted_patterns:  # Strings to look for under attribute_to_check.
                                       Conditional Globbing support.
                - 'ETCDCTL_READ_PASSWORD'
                - 'ETCDCTL_WRITE_PASSWORD'
                - '*PASSWORD*'  # Enable globbing by setting 'enable_globbing_in_nebula_masking'
                                  to True, default False

    blacklisted_patterns (for blacklisted_objects)

        For objects, the pattern applies to the variable name, and doesn't
        support regex. For example, you might have data formed like this::

            [{ value: 'SOME_PASSWORD', variable_name: 'ETCDCTL_READ_PASSWORD' }]

        The attribute_to_check would be ``variable_name`` and the pattern would
        be ``ETCDCTL_READ_PASSWORD``. The attribute_to_mask would be ``value``.
        All dicts with ``variable_name`` in the list of blacklisted_patterns
        would have the value under their ``value`` key masked.
    """
    try:
        mask = {}
        if topfile is None:
            # We will maintain backward compatibility by keeping two versions of
            # top files and mask files for now
            # Once all hubble servers are updated, we can remove old version of
            # top file and mask file
            # Similar to what we have for nebula and nebula_v2 for older versions and
            # newer versions of profiles
            topfile = 'salt://hubblestack_nebula_v2/top_v2.mask'
        mask_files = _get_top_data(topfile)
        mask_files = ['salt://hubblestack_nebula_v2/' + mask_file.replace('.', '/') + '.yaml'
                      for mask_file in mask_files]
        if not mask_files:
            mask_files = []
        for mask_file in mask_files:
            if 'salt://' in mask_file:
                orig_fh = mask_file
                mask_file = __mods__['cp.cache_file'](mask_file)
            if not mask_file:
                log.error('Could not find file %s.', orig_fh)
                return None
            if os.path.isfile(mask_file):
                with open(mask_file, 'r') as yfile:
                    f_data = yaml.safe_load(yfile)
                    if not isinstance(f_data, dict):
                        raise CommandExecutionError('File data is not formed as a dict {0}'
                                                    .format(f_data))
                    mask = _dict_update(mask, f_data, recursive_update=True, merge_lists=True)

        log.debug('Masking data: %s', mask)

        # Backwards compatibility with mask_by
        mask_with = mask.get('mask_with', mask.get('mask_by', 'REDACTED'))

        log.info("Total number of results to check for masking: %d", len(object_to_be_masked))
        globbing_enabled = __opts__.get('enable_globbing_in_nebula_masking')

        for blacklisted_object in mask.get('blacklisted_objects', []):
            query_names = blacklisted_object['query_names']
            column = blacklisted_object['column']  # Can be converted to list as well in future
            perform_masking_kwargs = {'blacklisted_object': blacklisted_object,
                                      'mask_with': mask_with,
                                      'globbing_enabled': globbing_enabled}
            if '*' in query_names:
                # This means wildcard is specified and each event should be masked, if applicable
                _mask_object_helper(object_to_be_masked, perform_masking_kwargs, column)
            else:
                # Perform masking on results of specific queries specified in 'query_names'
                for query_name in query_names:
                    _mask_object_helper(object_to_be_masked, perform_masking_kwargs,
                                        column, query_name)

    except Exception:
        log.exception('An error occured while masking the passwords.', exc_info=True)

    # Object masked in place, so we don't need to return the object
    return True


def _mask_object_helper(object_to_be_masked, perform_masking_kwargs, column, query_name=None):
    """
    Helper function used to mask an object
    """
    for obj in object_to_be_masked:
        if 'action' in obj:
            # This means data is generated by osquery daemon
            _mask_event_data(obj, query_name, column,
                             perform_masking_kwargs['blacklisted_object'],
                             perform_masking_kwargs['mask_with'],
                             perform_masking_kwargs['globbing_enabled'])
        else:
            # This means data is generated by osquery interactive shell
            kwargs = {'query_name': query_name, 'column': column,
                      'perform_masking_kwargs': perform_masking_kwargs,
                      'custom_args': {'should_break': True}}
            if query_name:
                # No log_error here, since we didn't reference a specific query
                kwargs['custom_args']['log_error'] = True
                data = obj.get(query_name, {'data': []})['data']
                _mask_interactive_shell_data(data, kwargs)
            else:
                kwargs['custom_args']['log_error'] = False
                for query_name, query_ret in obj.items():
                    data = query_ret['data']
                    _mask_interactive_shell_data(data, kwargs)


def _mask_interactive_shell_data(data, kwargs):
    """
    Function that masks the data generated by an interactive osquery shell
    """
    for query_result in data:
        status, _blacklisted_object, query_result = _mask_event_data_helper(
            event_data=query_result, **kwargs)
        if kwargs['custom_args']['log_error']:
            # if the column in not present in one data-object, it will
            # not be present in others as well. Break in that case.
            # This will happen only if mask.yaml is malformed
            if not status:
                break


def _mask_event_data(object_to_be_masked, query_name, column, blacklisted_object,
                     mask_with, globbing_enabled):
    """
    This method is responsible for masking potential secrets in event data generated by
    osquery daemon. This will handle logs format of both differential and snapshot types

    Logs generated by 'osqueryi' would not reach here due checks in parent method

    object_to_be_masked
        data structure to mask recursively

    query_name
        Perform masking only if query name in 'object_to_be_masked' matches the 'query_name'

    column
        column in which masking is to be performed

    blacklisted_object
        the blacklisted_objects entry from the mask.yaml

    mask_with
        masked values are replaced with this string

    globbing_enabled
        enable globbing in specified blacklisted patterns of mask file
    """
    if not query_name:
        query_name = object_to_be_masked['name']
    perform_masking_kwargs = {'blacklisted_object': blacklisted_object,
                              'mask_with': mask_with,
                              'globbing_enabled': globbing_enabled}

    if object_to_be_masked['action'] == 'snapshot' and query_name == object_to_be_masked['name']:
        # This means we have event data of type 'snapshot'
        for snap_object in object_to_be_masked['snapshot']:
            status, blacklisted_object, snap_object = _mask_event_data_helper(
                event_data=snap_object, query_name=query_name, column=column,
                perform_masking_kwargs=perform_masking_kwargs,
                custom_args={'should_break': True, 'log_error': True})
            if not status:
                break
    elif query_name == object_to_be_masked['name']:
        _status, _blacklisted_object, _q_result = _mask_event_data_helper(
            event_data=object_to_be_masked['columns'], query_name=query_name, column=column,
            perform_masking_kwargs=perform_masking_kwargs,
            custom_args={'should_break': False, 'log_error': True})
    else:
        # Unable to match query_name
        log.debug('Skipping masking, as event data is not for query: %s', query_name)


def _custom_blacklisted_object(blacklisted_object, mask_column):
    """
    Construct custom blacklisted patterns based on custom_mask_key value of blacklisted_object
    """
    for column_field in mask_column:
        try:
            if 'variable_name' in column_field and 'value' in column_field and \
                    column_field['variable_name'] == blacklisted_object['custom_mask_key']:
                log.debug("Constructing custom blacklisted patterns based on \
                          environment variable '%s'", blacklisted_object['custom_mask_key'])
                blacklisted_object['custom_blacklist'] = [
                    field.strip() for field in column_field['value'].replace(' ', ',').split(',')
                    if field.strip() and field.strip() != blacklisted_object['custom_mask_key']]
            else:
                log.debug("Custom mask variable not set in environment. Custom mask key used: %s",
                          blacklisted_object['custom_mask_key'])
        except Exception as exc:
            log.error("Failed to generate custom blacklisted patterns based on hubble mask key")
            log.error("Got error: %s", exc)

    return blacklisted_object


def _mask_event_data_helper(event_data, query_name, column, perform_masking_kwargs, custom_args):
    """
    Helper function for _mask_event_data that masks secrets in event data
    generated by osquery daemon taking into account the type - differential or snashot.

    perform_masking_kwargs
        Dictionary that acts as **kwargs for the _perform_masking function, holding
        blacklisted_object, mask_with and globbing_enabled

    custom_args
        A dictionary containing:
            'should_break' key with a True value if it should return when the column is not
             found in event_data and False if it should not return on that branch
            'log_error' key with a True value if it should log an error when the column is not
            found in event_data and False if that is not considered an error
    """
    blacklisted_object = perform_masking_kwargs['blacklisted_object']
    # Name of column that stores environment variables
    custom_mask_column = blacklisted_object.get('custom_mask_column', '')
    enable_local_masking = blacklisted_object.get('enable_local_masking', False)
    if enable_local_masking is True and custom_mask_column and custom_mask_column in event_data:
        log.debug("Checking if custom mask patterns are set in environment")
        mask_column = event_data[custom_mask_column]
        if mask_column and isinstance(mask_column, list):
            blacklisted_object = _custom_blacklisted_object(blacklisted_object, mask_column)
    if column not in event_data or \
            (isinstance(event_data[column], str) and
             event_data[column].strip() != ''):
        if custom_args['log_error']:
            log.error('masking data references a missing column %s in query %s',
                      column, query_name)
        if custom_args['should_break']:
            return False, blacklisted_object, event_data
    if isinstance(event_data[column], str):
        # If column is of 'string' type, then replace pattern in-place
        # No need for recursion here
        value = event_data[column]
        for pattern in blacklisted_object['blacklisted_patterns']:
            value = re.sub(pattern + '()', r'\1' + perform_masking_kwargs['mask_with'] + r'\3',
                           value)
        event_data[column] = value
    else:
        _perform_masking(event_data[column], **perform_masking_kwargs)
        blacklisted_object.pop('custom_blacklist', None)
    return True, blacklisted_object, event_data


def _perform_masking(object_to_mask, blacklisted_object, mask_with, globbing_enabled):
    """
    This function is used as a wrapper to _recursively_mask_objects function.
    It's main usage is to set 'blacklisted_patterns'.
    If custom blacklisted patterns are present they will used.

    Fallback to blacklisted_patterns specified in mask file if no custom hubble mask is provided.

    object_to_mask
        data structure to mask recursively

    blacklisted_object
        the blacklisted_objects entry from the mask.yaml

    blacklisted_patterns
        List of blacklisted patterns which will be used to identify if a field is to be masked

    mask_with
        masked values are replaced with this string

    globbing_enabled
        enable globbing in specified blacklisted patterns of mask file
    """
    enable_local_masking = blacklisted_object.get('enable_local_masking', False)
    enable_global_masking = blacklisted_object.get('enable_global_masking', False)
    blacklisted_patterns = None

    if enable_local_masking is True and enable_global_masking is True:
        # For now, we will be performing masking based on global list as well as dynamic list
        # present in process's environment variable
        # If there's no noticeable performance impact then we will continue using both else
        # switch to using either global blacklist or dynamic blacklist as specified by
        # blacklisted_object['custom_mask_key'] in process's environment
        if 'custom_blacklist' in blacklisted_object and blacklisted_object['custom_blacklist']:
            if blacklisted_object.get('blacklisted_patterns', None):
                blacklisted_patterns = blacklisted_object['blacklisted_patterns'] +\
                                       blacklisted_object['custom_blacklist']
                blacklisted_patterns = list(set(blacklisted_patterns))  # remove duplicates, if any
                log.debug("Appending custom blacklisted patterns in global blacklist for masking")
            else:
                blacklisted_patterns = blacklisted_object['custom_blacklist']
                log.debug("Local blacklist missing, using global blacklist for masking")
        else:
            if blacklisted_object.get('blacklisted_patterns', None):
                blacklisted_patterns = blacklisted_object['blacklisted_patterns']
                log.debug("No local blacklist found, using global blacklist only for masking")
    elif enable_global_masking is True:
        if blacklisted_object.get('blacklisted_patterns', None):
            blacklisted_patterns = blacklisted_object['blacklisted_patterns']
            log.debug("Only global masking is enabled.")
    elif enable_local_masking is True:
        if 'custom_blacklist' in blacklisted_object and blacklisted_object['custom_blacklist']:
            blacklisted_patterns = blacklisted_object['custom_blacklist']
            log.debug("Only local masking is enabled.")
    else:
        log.debug("Both global and local masking is disabled, skipping masking of results.")

    if blacklisted_patterns:
        _recursively_mask_objects(object_to_mask, blacklisted_object, blacklisted_patterns,
                                  mask_with, globbing_enabled)


def _recursively_mask_objects(object_to_mask, blacklisted_object, blacklisted_patterns,
                              mask_with, globbing_enabled):
    """
    This function is used by ``_mask_object()`` to mask passwords contained in
    an osquery data structure (formed as a list of dicts, usually). Since the
    lists can sometimes be nested, recurse through the lists.

    object_to_mask
        data structure to mask recursively

    blacklisted_object
        the blacklisted_objects entry from the mask.yaml

    blacklisted_patterns
        List of blacklisted patterns which will be used to identify if a field is to be masked

    mask_with
        masked values are replaced with this string

    globbing_enabled
        enable globbing in specified blacklisted patterns of mask file
    """
    if isinstance(object_to_mask, list):
        for child in object_to_mask:
            log.debug("Recursing object %s", child)
            _recursively_mask_objects(child, blacklisted_object, blacklisted_patterns,
                                      mask_with, globbing_enabled)
    elif globbing_enabled and blacklisted_object['attribute_to_check'] in object_to_mask:
        mask = False
        for blacklisted_pattern in blacklisted_patterns:
            if fnmatch.fnmatch(object_to_mask[blacklisted_object['attribute_to_check']],
                               blacklisted_pattern):
                mask = True
                log.info("Attribute %s will be masked.",
                         object_to_mask[blacklisted_object['attribute_to_check']])
                break
        if mask:
            for key in blacklisted_object['attributes_to_mask']:
                if key in object_to_mask:
                    object_to_mask[key] = mask_with
    elif (not globbing_enabled) and blacklisted_object['attribute_to_check'] in object_to_mask and \
            object_to_mask[blacklisted_object['attribute_to_check']] in blacklisted_patterns:
        for key in blacklisted_object['attributes_to_mask']:
            if key in object_to_mask:
                object_to_mask[key] = mask_with


def _dict_update(dest, upd, recursive_update=True, merge_lists=False):
    """
    Recursive version of the default dict.update

    Merges upd recursively into dest

    If recursive_update=False, will use the classic dict.update, or fall back
    on a manual merge (helpful for non-dict types like FunctionWrapper)

    If merge_lists=True, will aggregate list object types instead of replace.
    This behavior is only activated when recursive_update=True. By default
    merge_lists=False.
    """
    if (not isinstance(dest, collections.Mapping)) \
            or (not isinstance(upd, collections.Mapping)):
        raise TypeError('Cannot update using non-dict types in dictupdate.update()')
    updkeys = list(upd.keys())
    if not set(list(dest.keys())) & set(updkeys):
        recursive_update = False
    if recursive_update:
        for key in updkeys:
            val = upd[key]
            try:
                dest_subkey = dest.get(key, None)
            except AttributeError:
                dest_subkey = None
            if isinstance(dest_subkey, collections.Mapping) \
                    and isinstance(val, collections.Mapping):
                ret = _dict_update(dest_subkey, val, merge_lists=merge_lists)
                dest[key] = ret
            elif isinstance(dest_subkey, list) \
                    and isinstance(val, list):
                if merge_lists:
                    dest[key] = dest.get(key, []) + val
                else:
                    dest[key] = upd[key]
            else:
                dest[key] = upd[key]
    else:
        for k in upd:
            dest[k] = upd[k]
    return dest


def _osqueryd_running_status(pidfile):
    """
    This function will check whether osqueryd is running in *nix systems
    """
    log.info("checking if osqueryd is already running or not")
    osqueryd_running = False
    if os.path.isfile(pidfile):
        try:
            with open(pidfile, 'r') as pfile:
                xpid = pfile.readline().strip()
                try:
                    xpid = int(xpid)
                except Exception:
                    xpid = 0
                    log.warn('unable to parse pid="%d" in pidfile=%s', xpid, pidfile)
                if xpid:
                    log.info('pidfile=%s exists and contains pid=%d', pidfile, xpid)
                    if os.path.isdir("/proc/{pid}".format(pid=xpid)):
                        try:
                            with open("/proc/{pid}/cmdline".format(pid=xpid), 'r') as cmd_file:
                                cmdline = cmd_file.readline().strip().strip('\x00').replace(
                                    '\x00', ' ')
                                if 'osqueryd' in cmdline:
                                    log.info("process folder present and process is osqueryd")
                                    osqueryd_running = True
                                else:
                                    log.error("process is not osqueryd,"
                                              " attempting to start osqueryd")
                        except Exception:
                            log.error("process's cmdline cannot be determined,"
                                      " attempting to start osqueryd")
                    else:
                        log.error("process folder not present, attempting to start osqueryd")
                else:
                    log.error("pid cannot be determined, attempting to start osqueryd")
        except Exception:
            log.error("unable to open pidfile, attempting to start osqueryd")
    else:
        cmd = ['pkill', 'hubble_osqueryd']
        __mods__['cmd.run'](cmd, timeout=600)
        log.error("pidfile not found, attempting to start osqueryd")
    return osqueryd_running


def _osqueryd_restart_required(hashfile, flagfile):
    """
    This function will check whether osqueryd needs to be restarted
    """
    global OSQUERYD_NEEDS_RESTART
    log.info("checking if osqueryd needs to be restarted or not")
    if OSQUERYD_NEEDS_RESTART:
        OSQUERYD_NEEDS_RESTART = False
        return True
    try:
        with open(flagfile, "r") as open_file:
            file_content = open_file.read().lower().rstrip('\n\r ').strip('\n\r')
            if isFipsEnabled:
                hash_md5 = hashlib.md5(usedforsecurity=False)
            else:
                hash_md5 = hashlib.md5()
            hash_md5.update(file_content.encode('ISO-8859-1'))
            new_hash = hash_md5.hexdigest()

        if not os.path.isfile(hashfile):
            with open(hashfile, "w") as hfile:
                hfile.write(new_hash)
                return False
        else:
            with open(hashfile, "r") as hfile:
                old_hash = hfile.read()
                if old_hash != new_hash:
                    log.info('old hash is %s and new hash is %s', old_hash, new_hash)
                    log.info('changes detected in flag file')
                    return True
                else:
                    log.info('no changes detected in flag file')
    except Exception:
        log.error(
            "some error occured, unable to determine whether osqueryd need to be restarted,"
            " not restarting osqueryd")
    return False


def _osqueryd_running_status_windows(servicename):
    """
    This function will check whether osqueryd is running in windows systems
    """
    log.info("checking if osqueryd is already running or not")
    osqueryd_running = False
    cmd_status = "(Get-Service -Name " + servicename + ").Status"
    osqueryd_status = __mods__['cmd.run'](cmd_status, shell='powershell')
    if osqueryd_status == 'Running':
        osqueryd_running = True
        log.info('osqueryd already running')
    else:
        log.info('osqueryd not running')
        osqueryd_running = False

    return osqueryd_running


def _start_osqueryd(pidfile,
                    configfile,
                    flagfile,
                    logdir,
                    databasepath,
                    servicename):
    """
    This function will start osqueryd
    """
    log.info("osqueryd is not running, attempting to start osqueryd")
    if hubblestack.utils.platform.is_windows():
        log.info("requesting service manager to start osqueryd")
        cmd = ['net', 'start', servicename]
    else:
        cmd = ['/opt/osquery/hubble_osqueryd', '--pidfile={0}'.format(pidfile),
               '--logger_path={0}'.format(logdir),
               '--config_path={0}'.format(configfile), '--flagfile={0}'.format(flagfile),
               '--database_path={0}'.format(databasepath), '--daemonize']
    ret_dict = __mods__['cmd.run_all'](cmd, timeout=600)
    if ret_dict.get('retcode', None) != 0:
        log.error("Failed to start osquery daemon. Retcode: %s and error: %s", ret_dict.get(
            'retcode', None),
                  ret_dict.get('stderr', None))
    else:
        log.info("Successfully started osqueryd")


def _restart_osqueryd(pidfile,
                      configfile,
                      flagfile,
                      logdir,
                      databasepath,
                      hashfile,
                      servicename):
    """
    This function will restart osqueryd
    """
    log.info("osqueryd needs to be restarted, restarting now")

    with open(flagfile, "r") as open_file:
        file_content = open_file.read().lower().rstrip('\n\r ').strip('\n\r')
        if isFipsEnabled:
            hash_md5 = hashlib.md5(usedforsecurity=False)
        else:
            hash_md5 = hashlib.md5()
        hash_md5.update(file_content.encode('ISO-8859-1'))
        new_hash = hash_md5.hexdigest()

    with open(hashfile, "w") as hfile:
        hfile.write(new_hash)
    _stop_osqueryd(servicename, pidfile)
    _start_osqueryd(pidfile=pidfile, configfile=configfile, flagfile=flagfile,
                    logdir=logdir, databasepath=databasepath, servicename=servicename)


def _stop_osqueryd(servicename, pidfile):
    """
    Thid function will stop osqueryd.
    """
    if hubblestack.utils.platform.is_windows():
        stop_cmd = ['net', 'stop', servicename]
    else:
        stop_cmd = ['pkill', 'hubble_osqueryd']
    ret_stop = __mods__['cmd.run_all'](stop_cmd, timeout=600)
    if ret_stop.get('retcode', None) != 0:
        log.error("Failed to stop osqueryd. Retcode: %s and error: %s",
                  ret_stop.get('retcode', None), ret_stop.get('stderr', None))
    else:
        log.info("Successfully stopped osqueryd")
    if not hubblestack.utils.platform.is_windows():
        remove_pidfile_cmd = ['rm', '-rf', '{0}'.format(pidfile)]
        __mods__['cmd.run'](remove_pidfile_cmd, timeout=600)


def _parse_log(path_to_logfile,
               offset,
               backuplogdir,
               logfilethresholdinbytes,
               maxlogfilesizethreshold,
               backuplogfilescount,
               enablediskstatslogging):
    """
    Parse logs generated by osquery daemon.
    Path to log file to be parsed should be specified
    """
    event_data = []
    file_offset = offset
    rotate_log = False
    if os.path.exists(path_to_logfile):
        with open(path_to_logfile, "r") as file_des:
            if file_des:
                if os.stat(path_to_logfile).st_size > maxlogfilesizethreshold:
                    # This is done to handle scenarios where hubble process was in stopped state and
                    # osquery daemon was generating logs for that time frame.
                    # When hubble is started and this function gets executed,
                    # it might be possible that the log file is now huge.
                    # In this scenario hubble might take too much time to process the logs
                    # which may not be required
                    # To handle this, log file size is validated against max threshold size.
                    log.info(
                        "Log file size is above max threshold size that can be parsed by Hubble.")
                    log.info("Log file size: %f, max threshold: %f",
                             os.stat(path_to_logfile).st_size,
                             maxlogfilesizethreshold)
                    log.info("Rotating log and skipping parsing for this iteration")
                    # Closing explicitly to handle File in Use exception in windows
                    file_des.close()
                    _perform_log_rotation(path_to_logfile,
                                          file_offset,
                                          backuplogdir,
                                          backuplogfilescount,
                                          enablediskstatslogging,
                                          False)
                    # Reset file offset to start of file in case original file is rotated
                    file_offset = 0
                else:
                    if os.stat(path_to_logfile).st_size > logfilethresholdinbytes:
                        rotate_log = True
                    file_des.seek(offset)
                    for event in file_des.readlines():
                        event_data.append(event)
                    file_offset = file_des.tell()
                    # Closing explicitly to handle File in Use exception in windows
                    file_des.close()
                    if rotate_log:
                        log.info('Log file size above threshold, '
                                 'going to rotate log file: %s', path_to_logfile)
                        residue_events = _perform_log_rotation(path_to_logfile,
                                                               file_offset,
                                                               backuplogdir,
                                                               backuplogfilescount,
                                                               enablediskstatslogging,
                                                               True)
                        if residue_events:
                            log.info("Found few residue logs, updating the data object")
                            event_data += residue_events
                        # Reset file offset to start of file in case original file is rotated
                        file_offset = 0
                _set_cache_offset(path_to_logfile, file_offset)
            else:
                log.error('Unable to open log file for reading: %s', path_to_logfile)
    else:
        log.error("Log file doesn't exists: %s", path_to_logfile)

    return event_data


def _set_cache_offset(path_to_logfile, offset):
    """
    Cache file offset in specified file
    A file will be created in cache directory and following attributes will be stored in it
    offset, initial_crc (CRC for first 256 bytes of log file), last_crc (CRC for last 256 bytes of log file)
    """
    try:
        log_filename = os.path.basename(path_to_logfile)
        offsetfile = os.path.join(__opts__.get('cachedir'), 'osqueryd', 'offset', log_filename)
        log_file_initial_crc = 0
        log_file_last_crc = 0
        if(offset > 0):
            with open(path_to_logfile, 'rb') as log_file:
                log_file.seek(0)
                log_file_initial_crc = zlib.crc32(log_file.read(CRC_BYTES))

            if(offset > CRC_BYTES):
                with open(path_to_logfile, 'rb') as log_file:
                    log_file.seek(offset - CRC_BYTES)
                    log_file_last_crc = zlib.crc32(log_file.read(CRC_BYTES))

        offset_dict = {"offset" : offset, "initial_crc": log_file_initial_crc, "last_crc": log_file_last_crc}
        log.info("Storing following information for file {0}. Offset: {1}, Initial_CRC: {2}, Last_CRC: {3}".format(path_to_logfile, offset, log_file_initial_crc, log_file_last_crc))
        if not os.path.exists(os.path.dirname(offsetfile)):
            os.makedirs(os.path.dirname(offsetfile))

        with open(offsetfile, 'w') as json_file:
            json.dump(offset_dict, json_file)
    except Exception as e:
        log.error("Exception in creating offset file. Exception: {0}".format(e))
        tb = traceback.format_exc()
        log.error("Exception stacktrace: {0}".format(tb))

def _get_file_offset(path_to_logfile):
    """
    Fetch file offset for specified file
    """
    offset = 0
    try:
        log_filename = os.path.basename(path_to_logfile)
        offsetfile = os.path.join(__opts__.get('cachedir'), 'osqueryd', 'offset', log_filename)
        if not os.path.isfile(offsetfile):
            log.info("Offset file: {0} does not exist. Returning offset as 0.".format(offsetfile))
        else:
            with open(offsetfile, 'r') as file:
                offset_data = json.load(file)
            offset = offset_data.get('offset')
            initial_crc = offset_data.get('initial_crc')
            last_crc = offset_data.get('last_crc')
            log.debug("Offset file: {0} exist. Got following values: offset: {1}, initial_crc: {2}, last_crc: {3}".format(offsetfile, offset, initial_crc, last_crc))

            log_file_offset = 0
            log_file_initial_crc = 0
            with open(path_to_logfile, 'rb') as log_file:
                log_file.seek(log_file_offset)
                log_file_initial_crc = zlib.crc32(log_file.read(CRC_BYTES))

            if log_file_initial_crc == initial_crc:
                log.debug("Initial CRC for log file {0} matches. Now matching last CRC for the given offset {1}".format(path_to_logfile, offset))
                if offset > CRC_BYTES:
                    log_file_offset = offset - CRC_BYTES
                    log_file_last_crc = 0
                    with open(path_to_logfile, 'rb') as log_file:
                        log_file.seek(log_file_offset)
                        log_file_last_crc = zlib.crc32(log_file.read(CRC_BYTES))
                    if log_file_last_crc == last_crc:
                        log.info("Last CRC for log file {0} matches. Returning the offset value {1}".format(path_to_logfile, offset))
                    else:
                        log.error("Last CRC for log file {0} does not match. Got values: Expected: {1}, Actual: {2}. Returning offset as 0.".format(path_to_logfile, last_crc, log_file_last_crc))
                        offset = 0
                else:
                    log.info("Last offset of log file {0} is less than {1}. Returning 0.".format(path_to_logfile, CRC_BYTES))
                    offset = 0
            else:
                log.error("Initial CRC for log file {0} does not match. Got values: Expected: {1}, Actual {2}. Returning offset as 0.".format(path_to_logfile, initial_crc, log_file_initial_crc))
                offset = 0
    except Exception as e:
        log.error("Exception in getting offset for file: {0}. Returning offset as 0. Exception {1}".format(path_to_logfile, e))
        tb = traceback.format_exc()
        log.error("Exception stacktrace: {0}".format(tb))
        offset = 0
    return offset


def _perform_log_rotation(path_to_logfile,
                          offset,
                          backup_log_dir,
                          backup_log_files_count,
                          enable_disk_stats_logging,
                          read_residue_events):
    """
    Perform log rotation on specified file and create backup of file under
    specified backup directory.
    """
    residue_events = []
    if os.path.exists(path_to_logfile):
        log_filename = os.path.basename(path_to_logfile)
        if os.path.exists(backup_log_dir):
            list_of_backup_log_files = glob.glob(os.path.normpath(
                os.path.join(backup_log_dir, log_filename)) + "*")

            if list_of_backup_log_files:
                log.info("Backup log file count: %d and backup count threshold: %d",
                         len(list_of_backup_log_files), backup_log_files_count)
                list_of_backup_log_files.sort()
                log.info("Backup log file sorted list: %s", list_of_backup_log_files)
                if len(list_of_backup_log_files) >= backup_log_files_count:
                    list_of_backup_log_files = list_of_backup_log_files[
                        :len(list_of_backup_log_files) -
                        backup_log_files_count + 1]
                    for dfile in list_of_backup_log_files:
                        hubblestack.utils.files.remove(dfile)
                    log.info("Successfully deleted extra backup log files")

            residue_events = []
            log_filename = os.path.basename(path_to_logfile)

            backup_log_file = os.path.normpath(os.path.join(backup_log_dir, log_filename) +
                                               "-" + str(time.time()))
            hubblestack.utils.files.rename(path_to_logfile, backup_log_file)

            if read_residue_events:
                residue_events = _read_residue_logs(backup_log_file, offset)

            if enable_disk_stats_logging:
                # As of now, this method would send disk stats to Splunk (if configured)
                _disk_stats = check_disk_usage()
        else:
            log.error("Specified backup log directory does not exists."
                      " Log rotation will not be performed.")

    return residue_events


def _read_residue_logs(path_to_logfile, offset):
    """
    Read any logs that might have been written while creating backup log file
    """
    event_data = []
    if os.path.exists(path_to_logfile):
        with open(path_to_logfile, "r") as file_des:
            if file_des:
                log.info('Checking for any residue logs that might have been '
                         'added while log rotation was being performed')
                file_des.seek(offset)
                for event in file_des.readlines():
                    event_data.append(event)
    return event_data


def query(query):
    """
    Run the osquery `query` and return the results.

    query
        String containgin `SQL` query to be run by osquery

    """
    max_file_size = 104857600
    if 'attach' in query.lower() or 'curl' in query.lower():
        log.critical('Skipping potentially malicious osquery query which contains either'
                     ' \'attach\' or \'curl\': %s', query)
        return None
    query_ret = {'result': True}

    # Run the osqueryi query
    cmd = [__grains__['osquerybinpath'], '--read_max', max_file_size, '--json', query]
    res = __mods__['cmd.run_all'](cmd, timeout=600)
    if res['retcode'] == 0:
        query_ret['data'] = json.loads(res['stdout'])
    else:
        if 'Timed out' in res['stdout']:
            # this is really the best way to tell without getting fancy
            log.error('TIMEOUT during osqueryi execution %s', query)
        query_ret['result'] = False
        query_ret['error'] = res['stderr']

    return query_ret


def extensions(extensions_topfile=None, extensions_loadfile=None):
    """
    Given a topfile location, parse the topfile and lay down osquery extensions
    and other files as shown in the targeted profiles.

    The default topfile location is
    ``salt://hubblestack_nebula_v2/top.extensions``

    You can also specify a custom extensions loadfile for osquery, otherwise
    the configured path in ``osquery_extensions_loadfile`` will be used.

    If extensions_loadfile is defined, osqueryd will be restarted, if it is
    found to be running.

    Add ``remove: True`` to a file entry to delete the file. This allows for
    removing a no-longer-needed extension.

    By default, files can only be written under ``/opt/osquery/extensions`` to
    prevent accidental or malicious overwriting of system files. To change this
    whitelist, you can add ``osquery_extensions_path_whitelist`` in your
    hubble config. Form the configuration as a list of acceptable prefixes for
    files delivered by this module. Include trailing slashes, as we just use
    a "startswith" comparison::

        osquery_extensions_path_whitelist:
            - /opt/osquery/extensions/
            - /opt/osquery/augeas/

    Profile example::

        files:
            - path: salt://hubblestack_nebula_v2/extensions/test.ext
              dest: /opt/osquery/extensions/test.ext
              extension_autoload: True   # optional, defaults to False
              mode: '600'                # optional, default shown
              user: root                 # optional, default shown
              group: root                # optional, default shown
            - path: salt://hubblestack_nebula_v2/extensions/conf/test.json
              dest: /opt/osquery/extensions/conf/test.json
              extension_autoload: False  # optional, defaults to False
              mode: '600'                # optional, default shown
              user: root                 # optional, default shown
              group: root                # optional, default shown
    """
    if hubblestack.utils.platform.is_windows():
        log.error('Windows is not supported for nebula.extensions')
        return False

    if extensions_topfile is None:
        extensions_topfile = 'salt://hubblestack_nebula_v2/top.extensions'

    try:
        topdata = _get_top_data(extensions_topfile)
    except Exception:
        log.info('An error occurred fetching top data for nebula.extensions.', exc_into=True)
        return False

    if not topdata:
        return True

    topdata = ['salt://hubblestack_nebula_v2/' + config.replace('.', '/') + '.yaml'
               for config in topdata]

    files = _get_file_data(topdata)
    if files and isinstance(files, list):
        if extensions_loadfile is None:
            extensions_loadfile = __opts__.get('osquery_extensions_loadfile')

        autoload = _parse_file_data(files)

        if extensions_loadfile:
            try:
                with open(extensions_loadfile, 'w') as ext_file:
                    for extension in autoload:
                        ext_file.write(extension)
                        ext_file.write('\n')
            except Exception:
                log.error('Something went wrong writing osquery extensions.load.', exc_info=True)

            # Leave flag to restart osqueryd
            global OSQUERYD_NEEDS_RESTART
            OSQUERYD_NEEDS_RESTART = True
    return True


def _get_file_data(topdata):
    """
    Helper function that extracts the files from topdata and returns them as a list
    """
    extension_data = {}

    for ext_file in topdata:
        if 'salt://' in ext_file:
            orig_fh = ext_file
            ext_file = __mods__['cp.cache_file'](ext_file)
        if not ext_file:
            log.error('Could not find file %s.', orig_fh)
            continue
        if os.path.isfile(ext_file):
            with open(ext_file, 'r') as file_data:
                f_data = yaml.safe_load(file_data)
                if not isinstance(f_data, dict):
                    raise CommandExecutionError('File data is not formed as a dict {0}'
                                                .format(f_data))
                extension_data = _dict_update(extension_data,
                                              f_data,
                                              recursive_update=True,
                                              merge_lists=True)

    return extension_data.get('files')


def _parse_file_data(files):
    """
    Helper function that goes over each file in files, checks if whitelisted
    and if it should be removed.
    Returns a list of valid files that have 'extension_autoload' set to True
    """
    autoload = []
    for file_data in files:
        path = file_data.get('path')
        dest = file_data.get('dest')
        dest = os.path.abspath(dest)

        dest_ok = False
        whitelisted_paths = __opts__.get('osquery_extensions_path_whitelist',
                                         ['/opt/osquery/extensions/'])
        if not isinstance(whitelisted_paths, list):
            whitelisted_paths = list(whitelisted_paths)
        for whitelisted_path in whitelisted_paths:
            if dest.startswith(whitelisted_path):
                dest_ok = True
        if not dest_ok:
            log.error('Skipping file outside of osquery_extensions_path_whitelist: %s', dest)
            continue

        # Allow for file removals
        if file_data.get('remove'):
            if dest and os.path.exists(dest):
                try:
                    os.unlink(dest)
                except Exception:
                    pass
            continue

        if not path or not dest:
            log.error('path or dest missing in files entry: %s', file_data)
            continue

        result = _get_file(**file_data)

        if result and file_data.get('extension_autoload', False):
            autoload.append(dest)

    return autoload


def _get_file(path, dest, mode='600', user='root', group='root'):
    """
    Cache a file from a salt ``path`` to a local ``dest`` with the given
    attributes.
    """
    try:
        mode = str(mode)
        local_path = __mods__['cp.cache_file'](path)
        if not local_path:
            log.error('Couldn\'t cache %s to %s. This is probably due to '
                      'an issue finding the file in S3.', path, dest)
            return False
        shutil.copyfile(local_path, dest)
        ret = __mods__['file.check_perms'](name=local_path,
                                           ret=None,
                                           user=user,
                                           group=group,
                                           mode=mode)

        return ret[0]['result']
    except Exception:
        log.error('An error occurred getting file %s', path, exc_info=True)
        return False
