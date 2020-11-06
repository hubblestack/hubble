# -*- coding: utf-8 -*-
"""
Main entry point for the hubble daemon
"""

# import lockfile
import argparse
import copy
import json
import logging
import math
import traceback
import os
import pprint
import re
import random
import signal
import socket
import sys
import time
import uuid
from datetime import datetime

import salt.fileserver
import salt.fileserver.gitfs
import salt.modules.cmdmod
import salt.utils
import salt.utils.platform
import salt.utils.jid
import salt.utils.gitfs
import salt.utils.path
from croniter import croniter

import hubblestack.utils.signing
import hubblestack.splunklogging
import hubblestack.utils.osquery_lib
import hubblestack.log
import hubblestack.hec.opt
import hubblestack.utils.stdrec
from hubblestack import __version__
from hubblestack.hangtime import hangtime_wrapper
import hubblestack.status
import hubblestack.saltoverrides
import hubblestack.extmods.module_runner.runner
import hubblestack.extmods.module_runner.audit_runner
import hubblestack.extmods.module_runner.fdg_runner

log = logging.getLogger(__name__)
HSS = hubblestack.status.HubbleStatus(__name__, 'schedule', 'refresh_grains')

# Importing syslog fails on windows
if not salt.utils.platform.is_windows():
    import syslog

__opts__ = {}
# This should work fine until we go to multiprocessing
SESSION_UUID = str(uuid.uuid4())


def run():
    """
    Set up program, daemonize if needed
    """
    try:
        load_config()
    except Exception as exc:
        print('An Error occurred while loading the config: %s', exc)
        raise
    # Create cache directory if not present
    if not os.path.isdir(__opts__['cachedir']):
        os.makedirs(__opts__['cachedir'])
    try:
        main()
    except KeyboardInterrupt:
        pass

    clean_up_process(None, None)


def _clear_gitfs_locks():
    """ Clear old locks and log the changes """
    # Clear old locks
    if 'gitfs' in __opts__['fileserver_backend'] or 'git' in __opts__['fileserver_backend']:
        git_objects = [
            salt.utils.gitfs.GitFS(
                __opts__,
                __opts__['gitfs_remotes'],
                per_remote_overrides=salt.fileserver.gitfs.PER_REMOTE_OVERRIDES,
                per_remote_only=salt.fileserver.gitfs.PER_REMOTE_ONLY)]
        ret = {}
        for obj in git_objects:
            lock_type = 'update'
            cleared, errors = salt.fileserver.clear_lock(obj.clear_lock, 'gitfs', remote=None,
                                                         lock_type=lock_type)
            if cleared:
                ret.setdefault('cleared', []).extend(cleared)
            if errors:
                ret.setdefault('errors', []).extend(errors)
        if ret:
            log.info('One or more gitfs locks were removed: %s', ret)


def _emit_and_refresh_grains():
    """ When the grains refresh frequency has expired, refresh grains and emit to syslog """
    log.info('Refreshing grains')
    refresh_grains()
    last_grains_refresh = time.time()
    # Emit syslog at grains refresh frequency
    if not (salt.utils.platform.is_windows()) and \
            __opts__.get('emit_grains_to_syslog', True):
        default_grains_to_emit = ['system_uuid', 'hubble_uuid', 'session_uuid',
                                  'machine_id', 'splunkindex', 'cloud_details',
                                  'hubble_version', 'localhost', 'fqdn']
        grains_to_emit = []
        grains_to_emit.extend(
            __opts__.get('emit_grains_to_syslog_list', default_grains_to_emit))
        emit_to_syslog(grains_to_emit)
    return last_grains_refresh


def _update_fileserver(file_client):
    """ Update the filserver and the last_fc_update time """
    try:
        file_client.channel.fs.update()
        last_fc_update = time.time()
    except Exception:
        retry = __opts__.get('fileserver_retry_rate', 900)
        last_fc_update += retry
        log.exception('Exception thrown trying to update fileclient. '
                      'Trying again in %s seconds.', retry)
    return last_fc_update


def main():
    """
    Run the main hubble loop
    """
    # Initial fileclient setup
    _clear_gitfs_locks()
    # Setup fileclient
    log.info('Setting up the fileclient/fileserver')
    retry_count = __opts__.get('fileserver_retry_count_on_startup', None)
    retry_time = __opts__.get('fileserver_retry_rate_on_startup', 30)
    count = 0
    while True:
        try:
            file_client = salt.fileclient.get_file_client(__opts__)
            file_client.channel.fs.update()
            last_fc_update = time.time()
            break
        except Exception:
            if (retry_count is None or count < retry_count) and not __opts__['function']:
                log.exception('Exception thrown trying to setup fileclient. '
                              'Trying again in %s seconds.', retry_time)
                count += 1
                time.sleep(retry_time)
                continue
            else:
                log.exception('Exception thrown trying to setup fileclient. Exiting.')
                sys.exit(1)
    # Check for single function run
    if __opts__['function']:
        run_function()
        sys.exit(0)
    last_grains_refresh = time.time() - __opts__['grains_refresh_frequency']
    log.info('Starting main loop')
    pidfile_count = 0
    # pidfile_refresh in seconds, our scheduler deals in half-seconds
    pidfile_refresh = int(__opts__.get('pidfile_refresh', 60)) * 2
    while True:
        # Check if fileserver needs update
        if time.time() - last_fc_update >= __opts__['fileserver_update_frequency']:
            last_fc_update = _update_fileserver(file_client)
        pidfile_count += 1
        if __opts__['daemonize'] and pidfile_count > pidfile_refresh:
            pidfile_count = 0
            create_pidfile()
        if time.time() - last_grains_refresh >= __opts__['grains_refresh_frequency']:
            last_grains_refresh = _emit_and_refresh_grains()
        try:
            log.debug('Executing schedule')
            sf_count = schedule()
            if sf_count > 0:
                log.debug('Executed %d schedule item(s)', sf_count)
                hubblestack.log.workaround_salt_log_handler_queues()
        except Exception as exc:
            log.exception('Error executing schedule: %s', exc)
            if isinstance(exc, KeyboardInterrupt):
                raise exc
        time.sleep(__opts__.get('scheduler_sleep_frequency', 0.5))


def getsecondsbycronexpression(base, cron_exp):
    """
    this function will return the seconds according to the cron
    expression provided in the hubble config
    """
    cron_iter = croniter(cron_exp, base)
    next_datetime = cron_iter.get_next(datetime)
    epoch_base_datetime = time.mktime(base.timetuple())
    epoch_datetime = time.mktime(next_datetime.timetuple())
    seconds = int(epoch_datetime) - int(epoch_base_datetime)
    return seconds


def getlastrunbycron(base, seconds):
    """
    this function will use the cron_exp provided in the hubble config to
    execute the hubble processes as per the scheduled cron time
    """
    epoch_base_datetime = time.mktime(base.timetuple())
    epoch_datetime = epoch_base_datetime
    current_time = time.time()
    while (epoch_datetime + seconds) < current_time:
        epoch_datetime = epoch_datetime + seconds
    last_run = epoch_datetime
    return last_run


def getlastrunbybuckets(buckets, seconds):
    """
    this function will use the host's ip to place the host in a bucket
    where each bucket executes hubble processes at a different time
    """
    buckets = int(buckets) if int(buckets) != 0 else 256
    host_ip = socket.gethostbyname(socket.gethostname())
    ips = host_ip.split('.')
    bucket_sum = (int(ips[0]) * 256 * 256 * 256) + (int(ips[1]) * 256 * 256) + \
                 (int(ips[2]) * 256) + int(ips[3])
    bucket = bucket_sum % buckets
    log.debug('bucket number is %d out of %d', bucket, buckets)
    current_time = time.time()
    base_time = seconds * (math.floor(current_time / seconds))
    splay = seconds / buckets
    seconds_between_buckets = splay
    random_int = random.randint(0, splay - 1) if splay != 0 else 0
    bucket_execution_time = base_time + (seconds_between_buckets * bucket) + random_int
    if bucket_execution_time < current_time:
        last_run = bucket_execution_time
    else:
        last_run = bucket_execution_time - seconds
    return last_run


@HSS.watch
def schedule():
    """
    Rudimentary single-pass scheduler

    If we find we miss some of the salt scheduler features we could potentially
    pull in some of that code.

    Schedule data should be placed in the config with the following format:

    .. code-block:: yaml

        schedule:
          job1:
            function: hubble.audit
            seconds: 3600
            splay: 100
            min_splay: 50
            args:
              - cis.centos-7-level-1-scored-v2-1-0
            kwargs:
              verbose: True
              show_profile: True
            returner: splunk_nova_return
            run_on_start: True

    Note that ``args``, ``kwargs``,``min_splay`` and ``splay`` are all optional. However, a
    scheduled job must always have a ``function`` and a time in ``seconds`` of
    how often to run the job.

    function
        Function to run in the format ``<module>.<function>``. Technically any
        salt module can be run in this way, but we recommend sticking to hubble
        functions. For simplicity, functions are run in the main daemon thread,
        so overloading the scheduler can result in functions not being run in
        a timely manner.

    seconds
        Frequency with which the job should be run, in seconds

    splay
        Randomized splay for the job, in seconds. A random number between <min_splay> and
        <splay> will be chosen and added to the ``seconds`` argument, to decide
        the true frequency. The splay will be chosen on first run, and will
        only change when the daemon is restarted. Optional.

    min_splay
        This parameters works in conjunction with <splay>. If a <min_splay> is provided, and random
        between <min_splay> and <splay> is chosen. If <min_splay> is not provided, it
        defaults to zero. Optional.

    args
        List of arguments for the function. Optional.

    kwargs
        Dict of keyword arguments for the function. Optional.

    returner
        String with a single returner, or list of returners to which we should
        send the results. Optional.

    run_on_start
        Whether to run the scheduled job on daemon start. Defaults to False. Optional.
    """
    sf_count = 0
    base = datetime(2018, 1, 1, 0, 0)
    schedule_config = __opts__.get('schedule', {})
    if 'user_schedule' in __opts__ and isinstance(__opts__['user_schedule'], dict):
        schedule_config.update(__opts__['user_schedule'])
    for jobname, jobdata in schedule_config.items():
        try:
            # Error handling galore
            if not jobdata or not isinstance(jobdata, dict):
                log.error('Scheduled job %s does not have valid data', jobname)
                continue
            if 'function' not in jobdata or 'seconds' not in jobdata:
                log.error('Scheduled job %s is missing a ``function`` or ``seconds`` argument', jobname)
                continue
            func = jobdata['function']
            if func not in __salt__:
                log.error('Scheduled job %s has a function %s which could not be found.', jobname, func)
                continue
            try:
                if 'cron' in jobdata:
                    seconds = getsecondsbycronexpression(base, jobdata['cron'])
                else:
                    seconds = int(jobdata['seconds'])
                splay = int(jobdata.get('splay', 0))
                min_splay = int(jobdata.get('min_splay', 0))
            except ValueError:
                log.error('Scheduled job %s has an invalid value for seconds or splay.', jobname)
            args = jobdata.get('args', [])
            if not isinstance(args, list):
                log.error('Scheduled job %s has args not formed as a list: %s', jobname, args)
            kwargs = jobdata.get('kwargs', {})
            if not isinstance(kwargs, dict):
                log.error('Scheduled job %s has kwargs not formed as a dict: %s', jobname, kwargs)
            returners = jobdata.get('returner', [])
            if not isinstance(returners, list):
                returners = [returners]
            # Actually process the job
            run = _process_job(jobdata, splay, seconds, min_splay, base)
            if run:
                _execute_function(jobdata, func, returners, args, kwargs)
                sf_count += 1
        except Exception as e:
            log.error("Exception in running job: {0}. Exception: {1} . Continuing with next job....".format(jobname, e))
            tb = traceback.format_exc()
            log.error("Exception stacktrace: {0}".format(tb))
    return sf_count


def _execute_function(jobdata, func, returners, args, kwargs):
    """ Run the scheduled function """
    log.debug('Executing scheduled function %s', func)
    jobdata['last_run'] = time.time()
    ret = __salt__[func](*args, **kwargs)
    if __opts__['log_level'] == 'debug':
        log.debug('Job returned:\n%s', ret)
    for returner in returners:
        returner = '{0}.returner'.format(returner)
        if returner not in __returners__:
            log.error('Could not find %s returner.', returner)
            continue
        log.debug('Returning job data to %s', returner)
        returner_ret = {'id': __grains__['id'],
                        'jid': salt.utils.jid.gen_jid(__opts__),
                        'fun': func,
                        'fun_args': args + ([kwargs] if kwargs else []),
                        'return': ret}
        __returners__[returner](returner_ret)


def _process_job(jobdata, splay, seconds, min_splay, base):
    run = False
    if 'last_run' not in jobdata:
        if jobdata.get('run_on_start', False):
            if splay:
                # Run `splay` seconds in the future, by telling the scheduler we last ran it
                # `seconds - splay` seconds ago.
                jobdata['last_run'] = time.time() - (seconds - random.randint(min_splay, splay))
            else:
                # Run now
                run = True
                jobdata['last_run'] = time.time()
        else:
            if splay:
                # Run `seconds + splay` seconds in the future by telling the scheduler we last
                # ran it at now + `splay` seconds.
                jobdata['last_run'] = time.time() + random.randint(min_splay, splay)
            elif 'buckets' in jobdata:
                # Place the host in a bucket and fix the execution time.
                jobdata['last_run'] = getlastrunbybuckets(jobdata['buckets'], seconds)
                log.debug('last_run according to bucket is %s', jobdata['last_run'])
            elif 'cron' in jobdata:
                # execute the hubble process based on cron expression
                jobdata['last_run'] = getlastrunbycron(base, seconds)
            else:
                # Run in `seconds` seconds.
                jobdata['last_run'] = time.time()
    if jobdata['last_run'] < time.time() - seconds:
        run = True

    return run


def run_function():
    """
    Run a single function requested by the user
    """
    # Parse the args
    args = []
    kwargs = {}
    for arg in __opts__['args']:
        if '=' in arg:
            kwarg, _, value = arg.partition('=')
            kwargs[kwarg] = value
        else:
            args.append(arg)
    log.debug('Parsed args: %s | Parsed kwargs: %s', args, kwargs)
    log.info('Executing user-requested function %s', __opts__['function'])
    try:
        ret = __salt__[__opts__['function']](*args, **kwargs)
    except KeyError:
        log.error('Function %s is not available, or not valid.', __opts__['function'])
        sys.exit(1)
    if __opts__['return']:
        returner = '{0}.returner'.format(__opts__['return'])
        if returner not in __returners__:
            log.error('Could not find %s returner.', returner)
        else:
            log.info('Returning job data to %s', returner)
            returner_ret = {'id': __grains__['id'],
                            'jid': salt.utils.jid.gen_jid(__opts__),
                            'fun': __opts__['function'],
                            'fun_args': args + ([kwargs] if kwargs else []),
                            'return': ret}
            __returners__[returner](returner_ret)
    # TODO instantiate the salt outputter system?
    if __opts__['json_print']:
        print(json.dumps(ret))
    else:
        if not __opts__['no_pprint']:
            pprint.pprint(ret)
        else:
            print(ret)


def load_config():
    """
    Load the config from configfile and load into imported salt modules
    """
    # Parse arguments
    parsed_args = parse_args()

    # Let's find out the path of this module
    if 'SETUP_DIRNAME' in globals():
        # This is from the exec() call in Salt's setup.py
        this_file = os.path.join(SETUP_DIRNAME, 'salt', 'syspaths.py')  # pylint: disable=E0602
    else:
        this_file = __file__
    install_dir = os.path.dirname(os.path.realpath(this_file))
    _load_salt_config(parsed_args)
    global __opts__
    __opts__ = salt.config.minion_config(parsed_args.get('configfile'))
    __opts__.update(parsed_args)
    __opts__['conf_file'] = parsed_args.get('configfile')
    __opts__['install_dir'] = install_dir
    if __opts__['version']:
        print(__version__)
        clean_up_process(None, None)
        sys.exit(0)
    if __opts__['buildinfo']:
        try:
            from hubblestack import __buildinfo__
        except ImportError:
            __buildinfo__ = 'NOT SET'
        print(__buildinfo__)
        clean_up_process(None, None)
        sys.exit(0)
    scan_proc = __opts__.get('scan_proc', False)
    if __opts__['daemonize']:
        # before becoming a daemon, check for other procs and possibly send
        # them a signal 15 (otherwise refuse to run)
        if not __opts__.get('ignore_running', False):
            check_pidfile(kill_other=True, scan_proc=scan_proc)
        salt.utils.daemonize()
        create_pidfile()
    elif not __opts__['function'] and not __opts__['version'] and not __opts__['buildinfo']:
        # check the pidfile and possibly refuse to run (assuming this isn't a single function call)
        if not __opts__.get('ignore_running', False):
            check_pidfile(kill_other=False, scan_proc=scan_proc)
    # Optional sleep to wait for network
    time.sleep(int(__opts__.get('startup_sleep', 0)))
    _setup_signaling()
    # setup dirs for grains/returner/module
    _setup_dirs()
    _disable_boto_modules()
    _setup_logging(parsed_args)
    _setup_cached_uuid()
    refresh_grains(initial=True)
    if __salt__['config.get']('splunklogging', False):
        hubblestack.log.setup_splunk_logger()
        hubblestack.log.emit_to_splunk(__grains__, 'INFO', 'hubblestack.grains_report')
        __salt__['conf_publisher.publish']()


def _setup_signaling():
    """
    Hook the signal handler clean_up_process to trigger when certain signals are received
    """
    signal.signal(signal.SIGTERM, clean_up_process)
    signal.signal(signal.SIGINT, clean_up_process)
    signal.signal(signal.SIGABRT, clean_up_process)
    signal.signal(signal.SIGFPE, clean_up_process)
    signal.signal(signal.SIGILL, clean_up_process)
    signal.signal(signal.SIGSEGV, clean_up_process)
    if not salt.utils.platform.is_windows():
        signal.signal(signal.SIGHUP, clean_up_process)
        signal.signal(signal.SIGQUIT, clean_up_process)

def _disable_boto_modules():
    """ Disable the unneeded boto modules because they cause issues with the loader """
    # Disable all of salt's boto modules, they give nothing but trouble to the loader
    disable_modules = __opts__.get('disable_modules', [])
    disable_modules.extend(['boto3_elasticache', 'boto3_route53', 'boto3_sns', 'boto_apigateway',
                            'boto_asg', 'boto_cfn', 'boto_cloudfront', 'boto_cloudtrail',
                            'boto_cloudwatch_event', 'boto_cloudwatch', 'boto_cognitoidentity',
                            'boto_datapipeline', 'boto_dynamodb', 'boto_ec2', 'boto_efs',
                            'boto_elasticache', 'boto_elasticsearch_domain', 'boto_elb',
                            'boto_elbv2', 'boto_iam', 'boto_iot', 'boto_kinesis', 'boto_kms',
                            'boto_lambda', 'boto_rds', 'boto_route53', 'boto_s3_bucket', 'boto_s3',
                            'boto_secgroup', 'boto_sns', 'boto_sqs', 'boto_ssm', 'boto_vpc', ])
    __opts__['disable_modules'] = disable_modules


def _setup_cached_uuid():
    """ Get the cached uuid and cached system uui path, read the files
    and remove the cached uuid """

    # Check for a cloned system with existing hubble_uuid
    def _get_uuid_from_system():
        query = '"SELECT uuid AS system_uuid FROM osquery_info;" --header=false --csv'

        # Prefer our /opt/osquery/osqueryi if present
        osqueryipaths = ('/opt/osquery/osqueryi', 'osqueryi', '/usr/bin/osqueryi')
        for path in osqueryipaths:
            if salt.utils.path.which(path):
                live_uuid = salt.modules.cmdmod.run_stdout('{0} {1}'.format(path, query),
                                                           output_loglevel='quiet')
                live_uuid = str(live_uuid).upper()
                if len(live_uuid) == 36:
                    return live_uuid
                return None
        # If osquery isn't available, attempt to get uuid from /sys path (linux only)
        try:
            with open('/sys/devices/virtual/dmi/id/product_uuid', 'r') as product_uuid_file:
                file_uuid = product_uuid_file.read()
            file_uuid = str(file_uuid).upper()
            if len(file_uuid) == 36:
                return file_uuid
            return None
        except Exception:
            return None

    cached_uuid_path = os.path.join(os.path.dirname(__opts__['configfile']), 'hubble_cached_uuid')
    cached_system_uuid_path = os.path.join(os.path.dirname(__opts__['configfile']),
                                           'hubble_cached_system_uuid')
    try:
        if os.path.isfile(cached_uuid_path) and os.path.isfile(cached_system_uuid_path):
            with open(cached_uuid_path, 'r') as cached_uuid_file, \
                    open(cached_system_uuid_path, 'r') as cached_system_uuid_file:
                cached_uuid = cached_uuid_file.read()
                cached_system_uuid = cached_system_uuid_file.read()
            if cached_uuid != cached_system_uuid:
                live_uuid = _get_uuid_from_system()
                if live_uuid != cached_system_uuid:
                    log.error("potentially cloned system detected: System_uuid grain "
                              "previously saved on disk doesn't match live system value.\n"
                              "Resettig cached hubble_uuid value.")
                    os.remove(cached_uuid_path)

    except Exception:
        log.exception("Problem opening cache files while checking for previously cloned system")


def _load_salt_config(parsed_args):
    """ load the configs for salt.DEFAULT_MINION_OPTS """
    # Load unique data for Windows or Linux
    if salt.utils.platform.is_windows():
        if parsed_args.get('configfile') is None:
            parsed_args['configfile'] = 'C:\\Program Files (x86)\\Hubble\\etc\\hubble\\hubble.conf'
        salt.config.DEFAULT_MINION_OPTS['cachedir'] = 'C:\\Program Files (x86)\\hubble\\var\\cache'
        salt.config.DEFAULT_MINION_OPTS[
            'pidfile'] = 'C:\\Program Files (x86)\\hubble\\var\\run\\hubble.pid'
        salt.config.DEFAULT_MINION_OPTS[
            'log_file'] = 'C:\\Program Files (x86)\\hubble\\var\\log\\hubble.log'
        salt.config.DEFAULT_MINION_OPTS[
            'osquery_dbpath'] = 'C:\\Program Files (x86)\\hubble\\var\\hubble_osquery_db'
        salt.config.DEFAULT_MINION_OPTS[
            'osquerylogpath'] = 'C:\\Program Files (x86)\\hubble\\var\\log\\hubble_osquery'
        salt.config.DEFAULT_MINION_OPTS['osquerylog_backupdir'] = \
            'C:\\Program Files (x86)\\hubble\\var\\log\\hubble_osquery\\backuplogs'

    else:
        if parsed_args.get('configfile') is None:
            parsed_args['configfile'] = '/etc/hubble/hubble'
        salt.config.DEFAULT_MINION_OPTS['cachedir'] = '/var/cache/hubble'
        salt.config.DEFAULT_MINION_OPTS['pidfile'] = '/var/run/hubble.pid'
        salt.config.DEFAULT_MINION_OPTS['log_file'] = '/var/log/hubble'
        salt.config.DEFAULT_MINION_OPTS['osquery_dbpath'] = '/var/cache/hubble/osquery'
        salt.config.DEFAULT_MINION_OPTS['osquerylogpath'] = '/var/log/hubble_osquery'
        salt.config.DEFAULT_MINION_OPTS[
            'osquerylog_backupdir'] = '/var/log/hubble_osquery/backuplogs'

    salt.config.DEFAULT_MINION_OPTS['file_roots'] = {'base': []}
    salt.config.DEFAULT_MINION_OPTS['log_level'] = 'error'
    salt.config.DEFAULT_MINION_OPTS['file_client'] = 'local'
    salt.config.DEFAULT_MINION_OPTS['fileserver_update_frequency'] = 43200  # 12 hours
    salt.config.DEFAULT_MINION_OPTS['grains_refresh_frequency'] = 3600  # 1 hour
    salt.config.DEFAULT_MINION_OPTS['scheduler_sleep_frequency'] = 0.5
    salt.config.DEFAULT_MINION_OPTS['default_include'] = 'hubble.d/*.conf'
    salt.config.DEFAULT_MINION_OPTS['logfile_maxbytes'] = 100000000  # 100MB
    salt.config.DEFAULT_MINION_OPTS['logfile_backups'] = 1  # maximum rotated logs
    salt.config.DEFAULT_MINION_OPTS['delete_inaccessible_azure_containers'] = False
    # Globbing will not be supported in nebula masking
    salt.config.DEFAULT_MINION_OPTS['enable_globbing_in_nebula_masking'] = False
    salt.config.DEFAULT_MINION_OPTS['osquery_logfile_maxbytes'] = 50000000  # 50MB
    salt.config.DEFAULT_MINION_OPTS['osquery_logfile_maxbytes_toparse'] = 100000000  # 100MB
    salt.config.DEFAULT_MINION_OPTS['osquery_backuplogs_count'] = 2


def _setup_logging(parsed_args):
    """
    Get logging options and setup logging
    """
    # Convert -vvv to log level
    if __opts__['log_level'] is None:
        # Default to 'error'
        __opts__['log_level'] = 'error'
        # Default to more verbose if we're daemonizing
        if __opts__['daemonize']:
            __opts__['log_level'] = 'info'
    # Handle the explicit -vvv settings
    if __opts__['verbose']:
        if __opts__['verbose'] == 1:
            __opts__['log_level'] = 'warning'
        elif __opts__['verbose'] == 2:
            __opts__['log_level'] = 'info'
        elif __opts__['verbose'] >= 3:
            __opts__['log_level'] = 'debug'
    # Console logging is probably the same, but can be different
    console_logging_opts = {
        'log_level': __opts__.get('console_log_level', __opts__['log_level']),
        'log_format': __opts__.get('console_log_format',
                                   '%(asctime)s [%(levelname)-5s] %(message)s'),
        'date_format': __opts__.get('console_log_date_format', '%H:%M:%S'),
    }
    file_logging_opts = {
        'log_file': __opts__.get('log_file', '/var/log/hubble'),
        'log_level': __opts__['log_level'],
        'log_format': __opts__.get('log_format', '%(asctime)s,%(msecs)03d [%(levelname)-5s]'
                                                 ' [%(name)s:%(lineno)d]  %(message)s'),
        'date_format': __opts__.get('log_date_format', '%Y-%m-%d %H:%M:%S'),
        'max_bytes': __opts__.get('logfile_maxbytes', 100000000),
        'backup_count': __opts__.get('logfile_backups', 1),
    }

    # Setup logging
    hubblestack.log.setup_console_logger(**console_logging_opts)
    hubblestack.log.setup_file_logger(**file_logging_opts)

    with open(__opts__['log_file'], 'a') as _logfile:
        pass  # ensure the file exists before we set perms on it
    # 384 is 0o600 permissions, written without octal for python 2/3 compat
    os.chmod(__opts__['log_file'], 384)
    configfile = parsed_args.get('configfile')
    if configfile and os.path.isfile(configfile):
        os.chmod(configfile, 384)


def _setup_dirs():
    """
    Setup module/grain/returner dirs
    """
    hubble_mods_dirs = __opts__.get('hubble_mods_dirs', [])
    hubble_mods_dirs.append(os.path.join(os.path.dirname(__file__), 'extmods', 'hubble_mods'))
    __opts__['hubble_mods_dirs'] = hubble_mods_dirs
    comparators_dirs = __opts__.get('comparators_dirs', [])
    comparators_dirs.append(os.path.join(os.path.dirname(__file__), 'extmods', 'comparators'))
    __opts__['comparators_dirs'] = comparators_dirs
    module_dirs = __opts__.get('module_dirs', [])
    module_dirs.append(os.path.join(os.path.dirname(__file__), 'extmods', 'modules'))
    __opts__['module_dirs'] = module_dirs
    grains_dirs = __opts__.get('grains_dirs', [])
    grains_dirs.append(os.path.join(os.path.dirname(__file__), 'extmods', 'grains'))
    __opts__['grains_dirs'] = grains_dirs
    returner_dirs = __opts__.get('returner_dirs', [])
    returner_dirs.append(os.path.join(os.path.dirname(__file__), 'extmods', 'returners'))
    __opts__['returner_dirs'] = returner_dirs
    fileserver_dirs = __opts__.get('fileserver_dirs', [])
    fileserver_dirs.append(os.path.join(os.path.dirname(__file__), 'extmods', 'fileserver'))
    __opts__['fileserver_dirs'] = fileserver_dirs
    utils_dirs = __opts__.get('utils_dirs', [])
    utils_dirs.append(os.path.join(os.path.dirname(__file__), 'extmods', 'utils'))
    __opts__['utils_dirs'] = utils_dirs
    fdg_dirs = __opts__.get('fdg_dirs', [])
    fdg_dirs.append(os.path.join(os.path.dirname(__file__), 'extmods', 'fdg'))
    __opts__['fdg_dirs'] = fdg_dirs
    __opts__['file_roots']['base'].insert(0, os.path.join(os.path.dirname(__file__), 'files'))
    if 'roots' not in __opts__['fileserver_backend']:
        __opts__['fileserver_backend'].append('roots')


# 600s is a long time to get stuck loading grains and *not* be doing things
# like nova/pulsar. The SIGALRM will get caught by salt.loader.raw_mod as an
# error in a grain -- probably whichever is broken/hung.
#
# The grain will simply be missing, but the next refresh_grains will try to
# pick it up again.  If the hang is transient, the grain will populate
# normally.
#
# repeats=True meaning: restart the signal itimer after firing the timeout
# exception, which salt catches. In this way, we can catch multiple hangs with
# a single timer. Each timer restart is a new 600s timeout.
#
# tag='hubble:rg' will appear in the logs to differentiate this from other
# hangtime_wrapper timers (if any)
@hangtime_wrapper(timeout=600, repeats=True, tag='hubble:rg')
@HSS.watch
def refresh_grains(initial=False):
    """
    Refresh the grains, pillar, utils, modules, and returners
    """
    global __opts__
    global __grains__
    global __utils__
    global __salt__
    global __pillar__
    global __returners__
    global __context__

    persist, old_grains = {}, {}
    if not initial:
        old_grains = copy.deepcopy(__grains__)
        for grain in __opts__.get('grains_persist', []):
            if grain in __grains__:
                persist[grain] = __grains__[grain]
        # Hardcode these core grains as persisting
        persist = {grain: __grains__[grain] for grain in ['hubble_version', 'buildinfo']
                   if grain in __grains__}

    if initial:
        __context__ = {}
    if 'grains' in __opts__:
        __opts__.pop('grains')
    if 'pillar' in __opts__:
        __opts__.pop('pillar')
    __grains__ = salt.loader.grains(__opts__)
    __grains__.update(persist)
    __grains__['session_uuid'] = SESSION_UUID

    # This was a weird one. In older versions of hubble the version and
    # buildinfo were not persisted automatically which means that if you
    # installed a new version without restarting hubble, grains refresh could
    # cause that old daemon to report grains as if it were the new version.
    # Now if this hubble_marker_3 grain is present you know you can trust the
    # hubble_version and buildinfo.
    __grains__['hubble_marker_3'] = True

    old_grains.update(__grains__)
    __grains__ = old_grains

    # Check for default gateway and fall back if necessary
    if __grains__.get('ip_gw', None) is False and 'fallback_fileserver_backend' in __opts__:
        log.info('No default gateway detected; using fallback_fileserver_backend.')
        __opts__['fileserver_backend'] = __opts__['fallback_fileserver_backend']

    __opts__['hubble_uuid'] = __grains__.get('hubble_uuid', None)
    __opts__['system_uuid'] = __grains__.get('system_uuid', None)
    __pillar__ = {}
    __opts__['grains'] = __grains__
    __opts__['pillar'] = __pillar__
    __utils__ = salt.loader.utils(__opts__)
    __salt__ = salt.loader.minion_mods(__opts__, utils=__utils__, context=__context__)
    __returners__ = salt.loader.returners(__opts__, __salt__)

    # the only things that turn up in here (and that get preserved)
    # are pulsar.queue, pulsar.notifier and cp.fileclient_###########
    # log.debug('keys in __context__: {}'.format(list(__context__)))

    hubblestack.utils.stdrec.__grains__ = __grains__
    hubblestack.utils.stdrec.__opts__ = __opts__

    hubblestack.hec.opt.__grains__ = __grains__
    hubblestack.hec.opt.__salt__ = __salt__
    hubblestack.hec.opt.__opts__ = __opts__

    hubblestack.splunklogging.__grains__ = __grains__
    hubblestack.splunklogging.__salt__ = __salt__
    hubblestack.splunklogging.__opts__ = __opts__

    hubblestack.status.__opts__ = __opts__
    hubblestack.status.__salt__ = __salt__
    HSS.start_sigusr1_signal_handler()

    hubblestack.utils.signing.__opts__ = __opts__
    hubblestack.utils.signing.__salt__ = __salt__

    hubblestack.extmods.module_runner.runner.__salt__ = __salt__
    hubblestack.extmods.module_runner.runner.__grains__ = __grains__
    hubblestack.extmods.module_runner.runner.__opts__ = __opts__

    hubblestack.extmods.module_runner.audit_runner.__salt__ = __salt__
    hubblestack.extmods.module_runner.audit_runner.__grains__ = __grains__
    hubblestack.extmods.module_runner.audit_runner.__opts__ = __opts__

    hubblestack.extmods.module_runner.fdg_runner.__salt__ = __salt__
    hubblestack.extmods.module_runner.fdg_runner.__grains__ = __grains__
    hubblestack.extmods.module_runner.fdg_runner.__opts__ = __opts__
    hubblestack.extmods.module_runner.fdg_runner.__returners__ = __returners__

    hubblestack.log.refresh_handler_std_info()

    if not initial and __salt__['config.get']('splunklogging', False):
        hubblestack.log.emit_to_splunk(__grains__, 'INFO', 'hubblestack.grains_report')


def emit_to_syslog(grains_to_emit):
    """
    Emit grains and their values to syslog
    """
    try:
        # Avoid a syslog line to be longer than 1024 characters
        # Build syslog message
        syslog_list = ['hubble_syslog_message:']
        for grain in grains_to_emit:
            if grain in __grains__:
                if bool(__grains__[grain]) and isinstance(__grains__[grain], dict):
                    for key, value in __grains__[grain].items():
                        syslog_list.append('{0}={1}'.format(key, value))
                else:
                    syslog_list.append('{0}={1}'.format(grain, __grains__[grain]))
        syslog_message = ' '.join(syslog_list)
        log.info('Emitting some grains to syslog')
        syslog.openlog(logoption=syslog.LOG_PID)
        syslog.syslog(syslog_message)
    except Exception as exc:
        log.exception('An exception occurred on emitting a message to syslog: %s', exc)


def parse_args():
    """
    Parse command line arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--daemonize', action='store_true',
                        help='Whether to daemonize and background the process')
    parser.add_argument(
        '-c', '--configfile', default=None,
        help='Pass in an alternative configuration file. Default: /etc/hubble/hubble')
    parser.add_argument('-p', '--no-pprint', help='Turn off pprint for single-function output',
                        action='store_true')
    parser.add_argument('-v', '--verbose', action='count',
                        help=('Verbosity level. Use -v or -vv or -vvv for '
                              'varying levels of verbosity. Note that -vv '
                              'will be used by default in daemon mode.'))
    parser.add_argument('-r', '--return', default=None,
                        help='Pass in a returner for single-function runs')
    parser.add_argument('--version', action='store_true', help='Show version information')
    parser.add_argument('--buildinfo', action='store_true', help='Show build information')
    parser.add_argument('function', nargs='?', default=None,
                        help='Optional argument for the single function to be run')
    parser.add_argument('args', nargs='*', help='Any arguments necessary for a single function run')
    parser.add_argument(
        '-j', '--json-print', action='store_true',
        help='Optional argument to print the output of single run function in json format')
    parser.add_argument('--ignore_running', action='store_true',
                        help='Ignore any running hubble processes. This disables the pidfile.')
    return vars(parser.parse_args())


def check_pidfile(kill_other=False, scan_proc=True):
    """
    Check to see if there's already a pidfile. If so, check to see if the
    indicated process is alive and is Hubble.

    kill_other
        Default false, if set to true, attempt to kill detected running Hubble processes;
        otherwise exit with an error.

    """
    pidfile_path = __opts__['pidfile']
    if os.path.isfile(pidfile_path):
        with open(pidfile_path, 'r') as pidfile:
            xpid = pidfile.readline().strip()
            try:
                xpid = int(xpid)
            except (TypeError, ValueError):
                xpid = 0
                log.warn('unable to parse pid="%d" in pidfile=%s', xpid, pidfile_path)
            if xpid:
                log.warn('pidfile=%s exists and contains pid=%d', pidfile_path, xpid)
                kill_other_or_sys_exit(xpid, kill_other=kill_other)
    if scan_proc:
        scan_proc_for_hubbles(kill_other=kill_other)


def kill_other_or_sys_exit(xpid, hname=r'hubble', ksig=signal.SIGTERM, kill_other=True,
                           no_pgrp=True):
    """ Attempt to locate other hubbles using a cmdline regular expression and kill them when found.
        If killing the other processes fails (or kill_other is False), sys.exit instead.

        params:
          hname      :- the regular expression pattern to use to locate hubble (default: hubble)
          ksig       :- the signal to use to kill the other processes (default: signal.SIGTERM=15)
          kill_other :- (default: True); when false, don't attempt to kill,
                        just locate and exit (if found)
          no_pgrp    :- Avoid killing processes in this pgrp (avoid suicide). When no_pgrp is True,
                        invoke os.getprgp() to populate the actual value.

        caveats:
            There are some detailed notes on the process scanning in the function as comments.

            The most important caveat is that the hname regular expressions must match expecting
            that /proc/$$/cmdline text is null separated, not space separated.

            The other main caveat is that we can't actually examine the /proc/$$/exe file (that's
            always just a python). We have to scan the invocation text the kernel stored at launch.
            That text is not immutable and should not (normally) be relied upon for any purpose
            -- and this method does rely on it.
    """

    if no_pgrp is True:
        no_pgrp = os.getpgrp()
    if isinstance(no_pgrp, int):
        no_pgrp = str(no_pgrp)
    if os.path.isdir("/proc/{pid}".format(pid=xpid)):
        # NOTE: we'd prefer to check readlink(/proc/[pid]/exe), but that won't do
        # any good the /opt/whatever/bin/hubble is normally a text file with a
        # shebang; which the kernel picks up and uses to execute the real binary
        # with the "bin" file as an argument; so we'll have to live with cmdline
        pfile = '/proc/{pid}/cmdline'.format(pid=xpid)
        log.debug('searching %s for hubble procs matching %s', pfile, hname)
        with open(pfile, 'r') as pidfile:
            # NOTE: cmdline is actually null separated, not space separated
            # that shouldn't matter much for most hname regular expressions, but one never knows.
            cmdline = pidfile.readline().replace('\x00', ' ').strip()
        if re.search(hname, cmdline):
            if no_pgrp:
                pstatfile = '/proc/{pid}/stat'.format(pid=xpid)
                with open(pstatfile, 'r') as fh2:
                    # NOTE: man proc(5) § /proc/[pid]/stat
                    # (pid, comm, state, ppid, pgrp, session, tty_nr, tpgid, flags, ...)
                    pgrp = fh2.readline().split()[4]
                    if pgrp == no_pgrp:
                        log.debug("process (%s) exists and seems to be a hubble, "
                                  "but matches our process group (%s), ignoring", xpid, pgrp)
                        return False
            if kill_other:
                log.warn(
                    "process seems to still be alive and seems to be hubble,"
                    " attempting to shutdown")
                os.kill(int(xpid), ksig)
                time.sleep(1)
                if os.path.isdir("/proc/{pid}".format(pid=xpid)):
                    log.error("fatal error: failed to shutdown process (pid=%s) successfully", xpid)
                    sys.exit(1)
                else:
                    return True
            else:
                log.error("refusing to run while another hubble instance is running")
                sys.exit(1)
    else:
        # pidfile present, but nothing at that pid. Did we receive a sigterm?
        log.warning(
            'Pidfile found on startup, but no process at that pid. Did hubble receive a SIGTERM?')
    return False


def scan_proc_for_hubbles(_proc_path='/proc', hname=r'^/\S+python.*?/opt/.*?hubble',
                          kill_other=True, ksig=signal.SIGTERM):
    """ look for other hubble processes and kill them or sys.exit()"""
    no_pgrp = str(os.getpgrp())
    rpid = re.compile(r'\d+')
    if os.path.isdir('/proc'):
        for dirname, dirs, _files in os.walk('/proc'):
            if dirname == '/proc':
                for pid in [i for i in dirs if rpid.match(i)]:
                    kill_other_or_sys_exit(pid, hname=hname, kill_other=kill_other, ksig=ksig,
                                           no_pgrp=no_pgrp)
                break


def create_pidfile():
    """
    Create a pidfile after daemonizing
    """
    if not __opts__.get('ignore_running', False):
        pid = os.getpid()
        with open(__opts__['pidfile'], 'w') as pidfile:
            pidfile.write(str(pid))


def clean_up_process(received_signal, frame):
    """
    Log any signals received. If a SIGTERM or SIGINT is received, clean up
    pidfile and anything else that needs to be cleaned up.
    """
    if received_signal is None and frame is None:
        if not __opts__.get('ignore_running', False):
            if __opts__['daemonize']:
                if os.path.isfile(__opts__['pidfile']):
                    os.remove(__opts__['pidfile'])
        sys.exit(0)
    try:
        if __salt__['config.get']('splunklogging', False):
            hubblestack.log.emit_to_splunk('Signal {0} detected'.format(received_signal),
                                           'INFO', 'hubblestack.signals')
    finally:
        if received_signal == signal.SIGINT or received_signal == signal.SIGTERM:
            if not __opts__.get('ignore_running', False):
                if __opts__['daemonize']:
                    if os.path.isfile(__opts__['pidfile']):
                        os.remove(__opts__['pidfile'])
            sys.exit(0)
