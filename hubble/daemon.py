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

import salt.utils

log = logging.getLogger(__name__)

__opts__ = {}

def run():
    '''
    Set up program, daemonize if needed
    '''
    # Parse arguments
    global __opts__
    __opts__ = parse_args()

    # Set up logging
    logging_setup()



    # Create cache directory if not present
    # TODO: make this configurable
    if not os.path.isdir('/var/cache/hubble'):
        os.makedirs('/var/cache/hubble/')

    if __opts__.daemonize:
        salt.utils.daemonize()

    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)


def main():
    '''
    Run the main hubble loop
    '''
    while True:
        logging.debug('wheeee!')
        time.sleep(10)


def parse_args():
    '''
    Parse command line arguments
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--daemonize',
                        help='Whether to daemonize and background the process',
                        action='store_true')
    return parser.parse_args()


def logging_setup():
    '''
    Set up logger
    '''
    global log
    log.setLevel(logging.DEBUG)

    # Logging format
    formatter = logging.Formatter('[%(asctime)s] [%(name)s] [%(levelname)s] [%(message)s]', datefmt='%Y/%m/%d %H:%M:%S')

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
