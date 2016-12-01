# -*- coding: utf-8 -*-
'''
Main entry point for the hubble daemon
'''

#import lockfile
import argparse
import logging
import time
import os
import sys

import salt.fileclient
import salt.utils

import hubble.nova as nova

log = logging.getLogger(__name__)

__opts__ = {}


def run():
    '''
    Set up program, daemonize if needed
    '''
    # Don't put anything that needs config above this line
    load_config()

    # Set up logging
    logging_setup()

    # Create cache directory if not present
    # TODO: make this configurable
    if not os.path.isdir(__opts__['cachedir']):
        os.makedirs(__opts__['cachedir'])

    if __opts__['daemonize']:
        salt.utils.daemonize()

    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)


def main():
    '''
    Run the main hubble loop
    '''
    # Initial fileclient setup
    try:
        fc = salt.fileclient.get_file_client(__opts__)
        fc.channel.fs.update()
        last_fc_update = time.time()
    except Exception as exc:
        log.exception('Exception thrown trying to setup fileclient. Exiting.')
        sys.exit(1)

    while True:
        # Check if fileserver needs update
        if time.time() - last_fc_update >= __opts__['fileserver_update_frequency']:
            try:
                fc.channel.fs.update()
                last_fc_update = time.time()
            except Exception as exc:
                log.exception('Exception thrown trying to update fileclient.')

        try:
            log.info('Executing nova.top')
            log.debug(nova.top())
        except Exception as e:
            log.exception('Error executing nova.top')
        time.sleep(10)


def load_config():
    '''
    Load the config from configfile and load into imported salt modules
    '''
    # Parse arguments
    parsed_args = parse_args()
    log.debug('Parsed args: {0}'.format(parsed_args))

    salt.config.DEFAULT_MINION_OPTS['cachedir'] = '/var/cache/hubble'
    salt.config.DEFAULT_MINION_OPTS['file_client'] = 'local'
    salt.config.DEFAULT_MINION_OPTS['fileserver_update_frequency'] = 60

    global __opts__
    global __grains__
    global __utils__
    global __salt__
    global __pillar__
    __opts__ = salt.config.minion_config(parsed_args.get('configfile'))
    __opts__.update(parsed_args)
    __grains__ = salt.loader.grains(__opts__)
    __pillar__ = {}
    __opts__['grains'] = __grains__
    __opts__['pillar'] = __pillar__
    __utils__ = salt.loader.utils(__opts__)
    __salt__ = salt.loader.minion_mods(__opts__, utils=__utils__)

    # Load the globals into the hubble modules
    nova.__opts__ = __opts__
    nova.__grains__ = __grains__
    nova.__utils__ = __utils__
    nova.__salt__ = __salt__
    nova.__pillar__ = __pillar__


def parse_args():
    '''
    Parse command line arguments
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--daemonize',
                        help='Whether to daemonize and background the process',
                        action='store_true')
    parser.add_argument('-c', '--configfile',
                      default='/etc/hubble/hubble',
                      help=('Pass in an alternative configuration file. Default: %(default)s')
    )
    return vars(parser.parse_args())


def logging_setup():
    '''
    Set up logger
    '''
    global log
    log.setLevel(logging.DEBUG)

    # Logging format
    formatter = logging.Formatter('[%(asctime)s] [%(name)s] [%(levelname)s]: %(message)s', datefmt='%Y/%m/%d %H:%M:%S')

    # Log to file
    fh = logging.FileHandler('/var/log/hubble')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    log.addHandler(fh)

    # Log to stdout
    sh = logging.StreamHandler()
    sh.setLevel(logging.DEBUG)
    sh.setFormatter(formatter)
    log.addHandler(sh)
