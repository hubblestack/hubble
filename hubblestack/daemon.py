# -*- coding: utf-8 -*-
'''
Main entry point for the hubble daemon
'''
from __future__ import print_function

# import lockfile
import argparse
import copy
import logging
import time
import pprint
import os
import random
import signal
import sys
import uuid
import json
import socket
import math

import salt.fileclient
import salt.fileserver
import salt.fileserver.gitfs
import salt.utils
import salt.utils.platform
import salt.utils.jid
import salt.utils.gitfs
import salt.log.setup
import hubblestack.splunklogging
import hubblestack.hec.opt
from hubblestack import __version__
from croniter import croniter
from datetime import datetime
from hubblestack.hangtime import hangtime_wrapper
import hubblestack.status

log = logging.getLogger(__name__)
hubble_status = hubblestack.status.HubbleStatus(__name__, 'schedule', 'refresh_grains')

# Importing syslog fails on windows
if not salt.utils.platform.is_windows():
    import syslog

__opts__ = {}
# This should work fine until we go to multiprocessing
SESSION_UUID = str(uuid.uuid4())


def run():
    '''
    Set up program, daemonize if needed
    '''
    # Don't put anything that needs config or logging above this line
    try:
        load_config()
    except Exception as e:
        print('An Error occurred while loading the config: {0}'.format(e))
        raise

    # Create cache directory if not present
    if not os.path.isdir(__opts__['cachedir']):
        os.makedirs(__opts__['cachedir'])

    if __opts__['buildinfo']:
        try:
            from hubblestack import __buildinfo__
        except ImportError:
            __buildinfo__ = 'NOT SET'
        print(__buildinfo__)
        clean_up_process(None, None)
        sys.exit(0)

    try:
        main()
    except KeyboardInterrupt:
        pass

    clean_up_process(None, None)


def main():
    '''
    Run the main hubble loop
    '''
    # Initial fileclient setup
    # Clear old locks
    if 'gitfs' in __opts__['fileserver_backend'] or 'git' in __opts__['fileserver_backend']:
        git_objects = [
            salt.utils.gitfs.GitFS(
                __opts__,
                __opts__['gitfs_remotes'],
                per_remote_overrides=salt.fileserver.gitfs.PER_REMOTE_OVERRIDES,
                per_remote_only=salt.fileserver.gitfs.PER_REMOTE_ONLY
            )
        ]
        ret = {}
        for obj in git_objects:
            lock_type = 'update'
            cleared, errors = salt.fileserver.clear_lock(obj.clear_lock,
                                                         'gitfs',
                                                         remote=None,
                                                         lock_type=lock_type)
            if cleared:
                ret.setdefault('cleared', []).extend(cleared)
            if errors:
                ret.setdefault('errors', []).extend(errors)
        if ret:
            log.info('One or more gitfs locks were removed: {0}'.format(ret))

    # Setup fileclient
    log.info('Setting up the fileclient/fileserver')

    # Set up fileclient
    retry_count = __opts__.get('fileserver_retry_count_on_startup', None)
    retry_time = __opts__.get('fileserver_retry_rate_on_startup', 30)
    count = 0
    while True:
        try:
            fc = salt.fileclient.get_file_client(__opts__)
            fc.channel.fs.update()
            last_fc_update = time.time()
            break
        except Exception as exc:
            if (retry_count is None or count < retry_count) and not __opts__['function']:
                log.exception('Exception thrown trying to setup fileclient. '
                              'Trying again in {0} seconds.'
                              .format(retry_time))
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
            try:
                fc.channel.fs.update()
                last_fc_update = time.time()
            except Exception as exc:
                retry = __opts__.get('fileserver_retry_rate', 900)
                last_fc_update += retry
                log.exception('Exception thrown trying to update fileclient. '
                              'Trying again in {0} seconds.'
                              .format(retry))

        pidfile_count += 1
        if __opts__['daemonize'] and pidfile_count > pidfile_refresh:
            pidfile_count = 0
            create_pidfile()

        if time.time() - last_grains_refresh >= __opts__['grains_refresh_frequency']:
            log.info('Refreshing grains')
            refresh_grains()
            last_grains_refresh = time.time()

            # Emit syslog at grains refresh frequency
            if not (salt.utils.platform.is_windows()) and __opts__.get('emit_grains_to_syslog', True):
                 default_grains_to_emit=['system_uuid',
                                         'hubble_uuid',
                                         'session_uuid',
                                         'machine_id',
                                         'uuid',
                                         'splunkindex',
                                         'cloud_instance_id',
                                         'cloud_account_id',
                                         'localhost',
                                         'host']
                 grains_to_emit = []
                 grains_to_emit.extend(__opts__.get('emit_grains_to_syslog_list', default_grains_to_emit))
                 emit_to_syslog(grains_to_emit) 

        try:
            log.debug('Executing schedule')
            schedule()
        except Exception as e:
            log.exception('Error executing schedule')
        time.sleep(__opts__.get('scheduler_sleep_frequency', 0.5))

def getsecondsbycronexpression(base, cron_exp):
    '''
    this function will return the seconds according to the cron
    expression provided in the hubble config
    '''
    cron_iter = croniter(cron_exp, base)
    next_datetime  = cron_iter.get_next(datetime)
    epoch_base_datetime = time.mktime(base.timetuple())
    epoch_datetime = time.mktime(next_datetime.timetuple())
    seconds = int(epoch_datetime) - int(epoch_base_datetime)
    return seconds

def getlastrunbycron(base, seconds):
    '''
    this function will use the cron_exp provided in the hubble config to
    execute the hubble processes as per the scheduled cron time
    '''
    epoch_base_datetime = time.mktime(base.timetuple())
    epoch_datetime = epoch_base_datetime
    current_time = time.time()
    while (epoch_datetime + seconds) < current_time:
        epoch_datetime = epoch_datetime + seconds
    last_run = epoch_datetime
    return last_run

def getlastrunbybuckets(buckets, seconds):
    '''
    this function will use the host's ip to place the host in a bucket
    where each bucket executes hubble processes at a different time
    '''
    buckets = int(buckets) if int(buckets)!=0 else 256
    host_ip = socket.gethostbyname(socket.gethostname())
    ips = host_ip.split('.')
    bucket_sum = (int(ips[0])*256*256*256)+(int(ips[1])*256*256)+(int(ips[2])*256)+int(ips[3])
    bucket = bucket_sum%buckets
    log.debug('bucket number is {0} out of {1}'.format(bucket, buckets))
    current_time = time.time()
    base_time = seconds*(math.floor(current_time/seconds))
    splay = seconds/buckets
    seconds_between_buckets = splay
    random_int = random.randint(0,splay-1) if splay !=0 else 0
    bucket_execution_time = base_time+(seconds_between_buckets*bucket)+random_int
    if bucket_execution_time < current_time:
        last_run = bucket_execution_time
    else:
        last_run = bucket_execution_time - seconds
    return last_run

@hubble_status.watch
def schedule():
    '''
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
        Whether to run the scheduled job on daemon start. Defaults to False.
        Optional.
    '''
    base = datetime(2018, 1, 1, 0, 0)
    schedule_config = __opts__.get('schedule', {})
    if 'user_schedule' in __opts__ and isinstance(__opts__['user_schedule'], dict):
        schedule_config.update(__opts__['user_schedule'])
    for jobname, jobdata in schedule_config.iteritems():
        # Error handling galore
        if not jobdata or not isinstance(jobdata, dict):
            log.error('Scheduled job {0} does not have valid data'.format(jobname))
            continue
        if 'function' not in jobdata or 'seconds' not in jobdata:
            log.error('Scheduled job {0} is missing a ``function`` or '
                      '``seconds`` argument'.format(jobname))
            continue
        func = jobdata['function']
        if func not in __salt__:
            log.error('Scheduled job {0} has a function {1} which could not '
                      'be found.'.format(jobname, func))
            continue
        try:
            if 'cron' in jobdata:
                seconds = getsecondsbycronexpression(base, jobdata['cron'])
            else:
                seconds = int(jobdata['seconds'])
            splay = int(jobdata.get('splay', 0))
            min_splay = int(jobdata.get('min_splay', 0))
        except ValueError:
            log.error('Scheduled job {0} has an invalid value for seconds or '
                      'splay.'.format(jobname))
        args = jobdata.get('args', [])
        if not isinstance(args, list):
            log.error('Scheduled job {0} has args not formed as a list: {1}'
                      .format(jobname, args))
        kwargs = jobdata.get('kwargs', {})
        if not isinstance(kwargs, dict):
            log.error('Scheduled job {0} has kwargs not formed as a dict: {1}'
                      .format(jobname, kwargs))
        returners = jobdata.get('returner', [])
        if not isinstance(returners, list):
            returners = [returners]
        returner_retry = jobdata.get('returner_retry', False)

        # Actually process the job
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
                    log.debug('last_run according to bucket is {0}'.format(jobdata['last_run']))
                elif 'cron' in jobdata:
                    # execute the hubble process based on cron expression
                    jobdata['last_run'] = getlastrunbycron(base, seconds)
                else:
                    # Run in `seconds` seconds.
                    jobdata['last_run'] = time.time()

        if jobdata['last_run'] < time.time() - seconds:
            run = True

        if run:
            log.debug('Executing scheduled function {0}'.format(func))
            jobdata['last_run'] = time.time()
            ret = __salt__[func](*args, **kwargs)
            if __opts__['log_level'] == 'debug':
                log.debug('Job returned:\n{0}'.format(ret))
            for returner in returners:
                returner = '{0}.returner'.format(returner)
                if returner not in __returners__:
                    log.error('Could not find {0} returner.'.format(returner))
                    continue
                log.debug('Returning job data to {0}'.format(returner))
                returner_ret = {'id': __grains__['id'],
                                'jid': salt.utils.jid.gen_jid(__opts__),
                                'fun': func,
                                'fun_args': args + ([kwargs] if kwargs else []),
                                'return': ret,
                                'retry': returner_retry}
                __returners__[returner](returner_ret)


def run_function():
    '''
    Run a single function requested by the user
    '''
    # Parse the args
    args = []
    kwargs = {}
    for arg in __opts__['args']:
        if '=' in arg:
            kwarg, _, value = arg.partition('=')
            kwargs[kwarg] = value
        else:
            args.append(arg)

    log.debug('Parsed args: {0} | Parsed kwargs: {1}'.format(args, kwargs))
    log.info('Executing user-requested function {0}'.format(__opts__['function']))

    try:
        ret = __salt__[__opts__['function']](*args, **kwargs)
    except KeyError:
        log.error('Function {0} is not available, or not valid.'
                  .format(__opts__['function']))
        sys.exit(1)

    if __opts__['return']:
        returner = '{0}.returner'.format(__opts__['return'])
        if returner not in __returners__:
            log.error('Could not find {0} returner.'.format(returner))
        else:
            log.info('Returning job data to {0}'.format(returner))
            returner_ret = {'id': __grains__['id'],
                            'jid': salt.utils.jid.gen_jid(__opts__),
                            'fun': __opts__['function'],
                            'fun_args': args + ([kwargs] if kwargs else []),
                            'return': ret,
                            'retry': False}
            if __opts__.get('returner_retry', False):
                returner_ret['retry'] = True
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
    '''
    Load the config from configfile and load into imported salt modules
    '''
    # Parse arguments
    parsed_args = parse_args()

    # Let's find out the path of this module
    if 'SETUP_DIRNAME' in globals():
        # This is from the exec() call in Salt's setup.py
        this_file = os.path.join(SETUP_DIRNAME, 'salt', 'syspaths.py')  # pylint: disable=E0602
    else:
        this_file = __file__
    install_dir = os.path.dirname(os.path.realpath(this_file))

    # Load unique data for Windows or Linux
    if salt.utils.platform.is_windows():
        if parsed_args.get('configfile') is None:
            parsed_args['configfile'] = 'C:\\Program Files (x86)\\Hubble\\etc\\hubble\\hubble.conf'
        salt.config.DEFAULT_MINION_OPTS['cachedir'] = 'C:\\Program Files (x86)\\hubble\\var\\cache'
        salt.config.DEFAULT_MINION_OPTS['pidfile'] = 'C:\\Program Files (x86)\\hubble\\var\\run\\hubble.pid'
        salt.config.DEFAULT_MINION_OPTS['log_file'] = 'C:\\Program Files (x86)\\hubble\\var\\log\\hubble.log'
        salt.config.DEFAULT_MINION_OPTS['osquery_dbpath'] = 'C:\\Program Files (x86)\\hubble\\var\\hubble_osquery_db'
        salt.config.DEFAULT_MINION_OPTS['osquerylogpath'] = 'C:\\Program Files (x86)\\hubble\\var\\log\\hubble_osquery'
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
        salt.config.DEFAULT_MINION_OPTS['osquerylog_backupdir'] = '/var/log/hubble_osquery/backuplogs'

    salt.config.DEFAULT_MINION_OPTS['file_roots'] = {'base': []}
    salt.config.DEFAULT_MINION_OPTS['log_level'] = None
    salt.config.DEFAULT_MINION_OPTS['file_client'] = 'local'
    salt.config.DEFAULT_MINION_OPTS['fileserver_update_frequency'] = 43200  # 12 hours
    salt.config.DEFAULT_MINION_OPTS['grains_refresh_frequency'] = 3600  # 1 hour
    salt.config.DEFAULT_MINION_OPTS['scheduler_sleep_frequency'] = 0.5
    salt.config.DEFAULT_MINION_OPTS['default_include'] = 'hubble.d/*.conf'
    salt.config.DEFAULT_MINION_OPTS['logfile_maxbytes'] = 100000000 # 100MB
    salt.config.DEFAULT_MINION_OPTS['logfile_backups'] = 1 # maximum rotated logs
    salt.config.DEFAULT_MINION_OPTS['delete_inaccessible_azure_containers'] = False
    salt.config.DEFAULT_MINION_OPTS['enable_globbing_in_nebula_masking'] = False  # Globbing will not be supported in nebula masking
    salt.config.DEFAULT_MINION_OPTS['osquery_logfile_maxbytes'] = 50000000 # 50MB
    salt.config.DEFAULT_MINION_OPTS['osquery_logfile_maxbytes_toparse'] = 100000000 #100MB
    salt.config.DEFAULT_MINION_OPTS['osquery_backuplogs_count'] = 2
    

    global __opts__

    __opts__ = salt.config.minion_config(parsed_args.get('configfile'))
    __opts__.update(parsed_args)
    __opts__['conf_file'] = parsed_args.get('configfile')
    __opts__['install_dir'] = install_dir

    if __opts__['version']:
        print(__version__)
        clean_up_process(None, None)
        sys.exit(0)

    if __opts__['daemonize']:
        # before becoming a daemon, check for other procs and possibly send
        # then a signal 15 (otherwise refuse to run)
        if not __opts__.get('ignore_running', False):
            check_pidfile(kill_other=True)
        salt.utils.daemonize()
        create_pidfile()
    elif not __opts__['function'] and not __opts__['version']:
        # check the pidfile and possibly refuse to run
        # (assuming this isn't a single function call)
        if not __opts__.get('ignore_running', False):
            check_pidfile(kill_other=False)

    signal.signal(signal.SIGTERM, clean_up_process)
    signal.signal(signal.SIGINT, clean_up_process)

    # Optional sleep to wait for network
    time.sleep(int(__opts__.get('startup_sleep', 0)))

    # Convert -vvv to log level
    if __opts__['log_level'] is None:
        # Default to 'error'
        __opts__['log_level'] = 'error'
        # Default to more verbose if we're daemonizing
        if __opts__['daemonize']:
            __opts__['log_level'] = 'info'
    # Handle the explicit -vvv settings
    if __opts__['verbose'] == 1:
        __opts__['log_level'] = 'warning'
    elif __opts__['verbose'] == 2:
        __opts__['log_level'] = 'info'
    elif __opts__['verbose'] >= 3:
        __opts__['log_level'] = 'debug'

    # Setup module/grain/returner dirs
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

    # Disable all of salt's boto modules, they give nothing but trouble to the loader
    disable_modules = __opts__.get('disable_modules', [])
    disable_modules.extend([
        'boto3_elasticache',
        'boto3_route53',
        'boto_apigateway',
        'boto_asg',
        'boto_cfn',
        'boto_cloudtrail',
        'boto_cloudwatch_event',
        'boto_cloudwatch',
        'boto_cognitoidentity',
        'boto_datapipeline',
        'boto_dynamodb',
        'boto_ec2',
        'boto_efs',
        'boto_elasticache',
        'boto_elasticsearch_domain',
        'boto_elb',
        'boto_elbv2',
        'boto_iam',
        'boto_iot',
        'boto_kinesis',
        'boto_kms',
        'boto_lambda',
        'boto_rds',
        'boto_route53',
        'boto_s3_bucket',
        'boto_secgroup',
        'boto_sns',
        'boto_sqs',
        'boto_vpc',
    ])
    __opts__['disable_modules'] = disable_modules

    # Console logging is probably the same, but can be different
    console_logging_opts = {
        'log_level': __opts__.get('console_log_level', __opts__['log_level']),
        'log_format': __opts__.get('console_log_format'),
        'date_format': __opts__.get('console_log_date_format'),
    }

    # Setup logging
    salt.log.setup.setup_console_logger(**console_logging_opts)
    salt.log.setup.setup_logfile_logger(__opts__['log_file'],
                                        __opts__['log_level'],
                                        max_bytes=__opts__.get('logfile_maxbytes', 100000000),
                                        backup_count=__opts__.get('logfile_backups', 1))

    # 384 is 0o600 permissions, written without octal for python 2/3 compat
    os.chmod(__opts__['log_file'], 384)
    os.chmod(parsed_args.get('configfile'), 384)

    refresh_grains(initial=True)

    # splunk logs below warning, above info by default
    logging.SPLUNK = int(__opts__.get('splunk_log_level', 25))
    logging.addLevelName(logging.SPLUNK, 'SPLUNK')
    def splunk(self, message, *args, **kwargs):
        if self.isEnabledFor(logging.SPLUNK):
            self._log(logging.SPLUNK, message, args, **kwargs)
    logging.Logger.splunk = splunk
    if __salt__['config.get']('splunklogging', False):
        root_logger = logging.getLogger()
        handler = hubblestack.splunklogging.SplunkHandler()
        handler.setLevel(logging.SPLUNK)
        root_logger.addHandler(handler)
        class MockRecord(object):
            def __init__(self, message, levelname, asctime, name):
                self.message = message
                self.levelname = levelname
                self.asctime = asctime
                self.name = name
        handler.emit(MockRecord(__grains__, 'INFO', time.asctime(), 'hubblestack.grains_report'))

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
@hubble_status.watch
def refresh_grains(initial=False):
    '''
    Refresh the grains, pillar, utils, modules, and returners
    '''
    global __opts__
    global __grains__
    global __utils__
    global __salt__
    global __pillar__
    global __returners__
    global __context__

    persist = {}
    old_grains = {}
    if not initial:
        old_grains = copy.deepcopy(__grains__)
        for grain in __opts__.get('grains_persist', []):
            if grain in __grains__:
                persist[grain] = __grains__[grain]

    if initial:
        __context__ = {}
    if 'grains' in __opts__:
        __opts__.pop('grains')
    if 'pillar' in __opts__:
        __opts__.pop('pillar')
    __grains__ = salt.loader.grains(__opts__)
    __grains__.update(persist)
    __grains__['session_uuid'] = SESSION_UUID
    old_grains.update(__grains__)
    __grains__ = old_grains

    # Check for default gateway and fall back if necessary
    if __grains__.get('ip_gw', None) is False and 'fallback_fileserver_backend' in __opts__:
        log.info('No default gateway detected; using fallback_fileserver_backend.')
        __opts__['fileserver_backend'] = __opts__['fallback_fileserver_backend']

    __opts__['hubble_uuid'] = __grains__.get('hubble_uuid', None)
    __pillar__ = {}
    __opts__['grains'] = __grains__
    __opts__['pillar'] = __pillar__
    __utils__ = salt.loader.utils(__opts__)
    __salt__ = salt.loader.minion_mods(__opts__, utils=__utils__, context=__context__)
    __returners__ = salt.loader.returners(__opts__, __salt__)

    # the only things that turn up in here (and that get preserved)
    # are pulsar.queue, pulsar.notifier and cp.fileclient_###########
    # log.debug('keys in __context__: {}'.format(list(__context__)))

    hubblestack.hec.opt.__grains__ = __grains__
    hubblestack.hec.opt.__salt__ = __salt__
    hubblestack.hec.opt.__opts__ = __opts__

    hubblestack.splunklogging.__grains__ = __grains__
    hubblestack.splunklogging.__salt__ = __salt__
    hubblestack.splunklogging.__opts__ = __opts__

    hubblestack.status.__opts__ = __opts__
    hubble_status.start_sigusr1_signal_handler()

    if not initial and __salt__['config.get']('splunklogging', False):
        class MockRecord(object):
            def __init__(self, message, levelname, asctime, name):
                self.message = message
                self.levelname = levelname
                self.asctime = asctime
                self.name = name
        handler = hubblestack.splunklogging.SplunkHandler()
        handler.emit(MockRecord(__grains__, 'INFO', time.asctime(), 'hubblestack.grains_report'))

def emit_to_syslog(grains_to_emit):
    '''
    Emit grains and their values to syslog
    '''
    try:
        # Avoid a syslog line to be longer than 1024 characters
        # Build syslog message
        syslog_list = []
        syslog_list.append('hubble_syslog_message:')
        for grain in grains_to_emit:
            if grain in __grains__:
                syslog_list.append('{0}={1}'.format(grain, __grains__[grain]))
        syslog_message = ' '.join(syslog_list)
        log.info('Emitting some grains to syslog')
        syslog.openlog(logoption = syslog.LOG_PID)
        syslog.syslog(syslog_message)
    except Exception as e:
        log.exception('An exception occurred on emitting a message to syslog: {0}'.format(e))

def parse_args():
    '''
    Parse command line arguments
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--daemonize',
                        action='store_true',
                        help='Whether to daemonize and background the process')
    parser.add_argument('-c', '--configfile',
                        default=None,
                        help='Pass in an alternative configuration file. Default: /etc/hubble/hubble')
    parser.add_argument('-p', '--no-pprint',
                        help='Turn off pprint for single-function output',
                        action='store_false')
    parser.add_argument('-v', '--verbose',
                        action='count',
                        help=('Verbosity level. Use -v or -vv or -vvv for '
                              'varying levels of verbosity. Note that -vv '
                              'will be used by default in daemon mode.'))
    parser.add_argument('-r', '--return',
                        default=None,
                        help='Pass in a returner for single-function runs')
    parser.add_argument('--version',
                        action='store_true',
                        help='Show version information')
    parser.add_argument('--buildinfo',
                        action='store_true',
                        help='Show build information')
    parser.add_argument('function',
                        nargs='?',
                        default=None,
                        help='Optional argument for the single function to be run')
    parser.add_argument('args',
                        nargs='*',
                        help='Any arguments necessary for a single function run')
    parser.add_argument('-j', '--json-print',
                        action='store_true',
                        help='Optional argument to print the output of single run function in json format')
    parser.add_argument('--ignore_running',
                        action='store_true',
                        help='Ignore any running hubble processes. This disables the pidfile.')
    parser.add_argument('--returner_retry',
                        action='store_true',
                        help='Enable retry on the returner for one-off jobs')
    return vars(parser.parse_args())

def check_pidfile(kill_other=False):
    '''
    Check to see if there's already a pidfile. If so, check to see if the
    indicated process is alive and is Hubble.

    kill_other
        Default false, if set to true, attempt to kill detected running Hubble
        processes; otherwise exit with an error.

    '''
    pidfile = __opts__['pidfile']
    if os.path.isfile(pidfile):
        with open(pidfile, 'r') as f:
            xpid = f.readline().strip()
            try:
                xpid = int(xpid)
            except:
                xpid = 0
                log.warn('unable to parse pid="{pid}" in pidfile={file}'.format(pid=xpid,file=pidfile))
            if xpid:
                log.warn('pidfile={file} exists and contains pid={pid}'.format(file=pidfile, pid=xpid))
                if os.path.isdir("/proc/{pid}".format(pid=xpid)):
                    with open("/proc/{pid}/cmdline".format(pid=xpid),'r') as f2:
                        cmdline = f2.readline().strip().strip('\x00').replace('\x00',' ')
                        if 'hubble' in cmdline:
                            if kill_other:
                                log.warn("process seems to still be alive and is hubble, attempting to shutdown")
                                os.kill(int(xpid), signal.SIGTERM)
                                time.sleep(1)
                                if os.path.isdir("/proc/{pid}".format(pid=xpid)):
                                    log.error("failed to shutdown process successfully; abnormal program exit")
                                    sys.exit(1)
                                else:
                                    log.info("shutdown seems to have succeeded, proceeding with startup")
                            else:
                                log.error("refusing to run while another hubble instance is running")
                                sys.exit(1)
                        else:
                            log.info("process does not appear to be hubble, ignoring")

def create_pidfile():
    '''
    Create a pidfile after daemonizing
    '''
    if not __opts__.get('ignore_running', False):
        pid = os.getpid()
        with open(__opts__['pidfile'], 'w') as f:
            f.write(str(pid))


def clean_up_process(signal, frame):
    '''
    Clean up pidfile and anything else that needs to be cleaned up
    '''
    if not __opts__.get('ignore_running', False):
        if __opts__['daemonize']:
            if os.path.isfile(__opts__['pidfile']):
                os.remove(__opts__['pidfile'])
    sys.exit(0)