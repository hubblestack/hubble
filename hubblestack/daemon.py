# -*- coding: utf-8 -*-
'''
Main entry point for the hubble daemon
'''
from __future__ import print_function

#import lockfile
import argparse
import logging
import time
import pprint
import os
import random
import signal
import sys

import salt.fileclient
import salt.utils
import salt.utils.jid
import salt.log.setup
from hubblestack import __version__

log = logging.getLogger(__name__)

__opts__ = {}


def run():
    '''
    Set up program, daemonize if needed
    '''
    # Don't put anything that needs config or logging above this line
    load_config()

    # Create cache directory if not present
    if not os.path.isdir(__opts__['cachedir']):
        os.makedirs(__opts__['cachedir'])

    if __opts__['version']:
        print(__version__)
        clean_up_process()
        sys.exit(0)

    if __opts__['daemonize']:
        salt.utils.daemonize()

    create_pidfile()
    signal.signal(signal.SIGTERM, clean_up_process)
    signal.signal(signal.SIGINT, clean_up_process)

    try:
        main()
    except KeyboardInterrupt:
        pass

    clean_up_process()


def main():
    '''
    Run the main hubble loop
    '''
    # Initial fileclient setup
    log.info('Setting up the fileclient/fileserver')
    try:
        fc = salt.fileclient.get_file_client(__opts__)
        fc.channel.fs.update()
        last_fc_update = time.time()
    except Exception as exc:
        log.exception('Exception thrown trying to setup fileclient. Exiting.')
        sys.exit(1)

    # Check for single function run
    if __opts__['function']:
        run_function()
        sys.exit(0)

    log.info('Starting main loop')
    while True:
        # Check if fileserver needs update
        if time.time() - last_fc_update >= __opts__['fileserver_update_frequency']:
            try:
                fc.channel.fs.update()
                last_fc_update = time.time()
            except Exception as exc:
                log.exception('Exception thrown trying to update fileclient.')

        try:
            log.debug('Executing schedule')
            schedule()
        except Exception as e:
            log.exception('Error executing schedule')
        time.sleep(0.5)


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
            args:
              - cis.centos-7-level-1-scored-v2-1-0
            kwargs:
              verbose: True
              show_profile: True
            returner: splunk_nova_return
            run_on_start: True

    Note that ``args``, ``kwargs``, and ``splay`` are all optional. However, a
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
        Randomized splay for the job, in seconds. A random number between 0 and
        <splay> will be chosen and added to the ``seconds`` argument, to decide
        the true frequency. The splay will be chosen on first run, and will
        only change when the daemon is restarted. Optional.

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
    schedule_config = __opts__.get('schedule', {})
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
            seconds = int(jobdata['seconds'])
            splay = int(jobdata.get('splay', 0))
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

        # Actually process the job
        run = False
        if 'last_run' not in jobdata:
            if jobdata.get('run_on_start', False):
                run = True
            jobdata['last_run'] = time.time()
        if 'set_splay' not in jobdata:
            jobdata['set_splay'] = random.randint(0, splay)
        splay = jobdata['set_splay']

        if jobdata['last_run'] < time.time() - seconds - splay:
            run = True

        if run:
            log.info('Executing scheduled function {0}'.format(func))
            jobdata['last_run'] = time.time()
            ret = __salt__[func](*args, **kwargs)
            log.debug('Job returned:\n{0}'.format(ret))
            for returner in returners:
                returner = '{0}.returner'.format(returner)
                if returner not in __returners__:
                    log.error('Could not find {0} returner.'.format(returner))
                    continue
                log.info('Returning job data to {0}'.format(returner))
                returner_ret = {'id': __grains__['id'],
                                'jid': salt.utils.jid.gen_jid(),
                                'fun': func,
                                'fun_args': args + ([kwargs] if kwargs else []),
                                'return': ret}
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

    ret = __salt__[__opts__['function']](*args, **kwargs)

    if __opts__['return']:
        returner = '{0}.returner'.format(__opts__['return'])
        if returner not in __returners__:
            log.error('Could not find {0} returner.'.format(returner))
        else:
            log.info('Returning job data to {0}'.format(returner))
            returner_ret = {'id': __grains__['id'],
                            'jid': salt.utils.jid.gen_jid(),
                            'fun': __opts__['function'],
                            'fun_args': args + ([kwargs] if kwargs else []),
                            'return': ret}
            __returners__[returner](returner_ret)

    # TODO instantiate the salt outputter system?
    if(__opts__['no_pprint']):
        pprint.pprint(ret)
    else:
        print(ret)


def load_config():
    '''
    Load the config from configfile and load into imported salt modules
    '''
    # Parse arguments
    parsed_args = parse_args()

    salt.config.DEFAULT_MINION_OPTS['cachedir'] = '/var/cache/hubble'
    salt.config.DEFAULT_MINION_OPTS['pidfile'] = '/var/run/hubble.pid'
    salt.config.DEFAULT_MINION_OPTS['log_file'] = '/var/log/hubble'
    salt.config.DEFAULT_MINION_OPTS['file_client'] = 'local'
    salt.config.DEFAULT_MINION_OPTS['fileserver_update_frequency'] = 60

    global __opts__
    global __grains__
    global __utils__
    global __salt__
    global __pillar__
    global __returners__

    __opts__ = salt.config.minion_config(parsed_args.get('configfile'))
    __opts__.update(parsed_args)

    # Convert -vvv to log level
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

    # Setup module dirs
    module_dirs = __opts__.get('module_dirs', [])
    module_dirs.append(os.path.join(os.path.dirname(__file__), 'extmods'))
    __opts__['module_dirs'] = module_dirs
    __opts__['file_roots']['base'].insert(0, os.path.join(os.path.dirname(__file__), 'files'))
    if 'roots' not in __opts__['fileserver_backend']:
        __opts__['fileserver_backend'].append('roots')

    # Setup logging
    salt.log.setup.setup_console_logger(__opts__['log_level'])
    salt.log.setup.setup_logfile_logger(__opts__['log_file'],
                                        __opts__['log_level'])

    __grains__ = salt.loader.grains(__opts__)
    __pillar__ = {}
    __opts__['grains'] = __grains__
    __opts__['pillar'] = __pillar__
    __utils__ = salt.loader.utils(__opts__)
    __salt__ = salt.loader.minion_mods(__opts__, utils=__utils__)
    __returners__ = salt.loader.returners(__opts__, __salt__)


def parse_args():
    '''
    Parse command line arguments
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--daemonize',
                        action='store_true',
                        help='Whether to daemonize and background the process')
    parser.add_argument('-c', '--configfile',
                        default='/etc/hubble/hubble',
                        help='Pass in an alternative configuration file. Default: %(default)s')
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
    parser.add_argument('function',
                        nargs='?',
                        default=None,
                        help='Optional argument for the single function to be run')
    parser.add_argument('args',
                        nargs='*',
                        help='Any arguments necessary for a single function run')
    return vars(parser.parse_args())


def create_pidfile():
    '''
    Create a pidfile after daemonizing
    '''
    pid = os.getpid()
    with open(__opts__['pidfile'], 'w') as f:
        f.write(str(pid))


def clean_up_process(signal, frame):
    '''
    Clean up pidfile and anything else that needs to be cleaned up
    '''
    if os.path.isfile(__opts__['pidfile']):
        os.remove(__opts__['pidfile'])
    sys.exit(0)
