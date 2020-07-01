# -*- coding: utf-8 -*-
'''
    :codeauthor: Pedro Algarvio (pedro@algarvio.me)


    salt.syspaths
    ~~~~~~~~~~~~~

    Salt's defaults system paths

    This module allows defining Salt's default paths at build time by writing a
    ``_syspath.py`` file to the filesystem. This is useful, for example, for
    setting platform-specific defaults that differ from the standard Linux
    paths.

    These values are static values and must be considered as secondary to any
    paths that are set in the master/minion config files.
'''

# Import python libs
from __future__ import absolute_import, print_function, unicode_literals
import sys
import os.path

__PLATFORM = sys.platform.lower()

# Let's find out the path of this module
if 'SETUP_DIRNAME' in globals():
    # This is from the exec() call in Salt's setup.py
    __THIS_FILE = os.path.join(SETUP_DIRNAME, 'hubble', 'syspaths.py')  # pylint: disable=E0602
else:
    __THIS_FILE = __file__

INSTALL_DIR = os.path.dirname(os.path.realpath(__THIS_FILE))

if __PLATFORM.startswith('win'):
    ROOT_DIR = r'c:\salt'
else:
    ROOT_DIR = '/'

if __PLATFORM.startswith('win'):
    CONFIG_DIR = os.path.join(ROOT_DIR, 'conf')
elif 'freebsd' in __PLATFORM:
    CONFIG_DIR = os.path.join(ROOT_DIR, 'usr', 'local', 'etc', 'hubble')
elif 'netbsd' in __PLATFORM:
    CONFIG_DIR = os.path.join(ROOT_DIR, 'usr', 'pkg', 'etc', 'hubble')
elif 'sunos5' in __PLATFORM:
    CONFIG_DIR = os.path.join(ROOT_DIR, 'opt', 'local', 'etc', 'hubble')
else:
    CONFIG_DIR = os.path.join(ROOT_DIR, 'etc', 'hubble')

if __PLATFORM.startswith('win'):
    SHARE_DIR = os.path.join(ROOT_DIR, 'share')
elif 'freebsd' in __PLATFORM:
    SHARE_DIR = os.path.join(ROOT_DIR, 'usr', 'local', 'share', 'hubble')
elif 'netbsd' in __PLATFORM:
    SHARE_DIR = os.path.join(ROOT_DIR, 'usr', 'share', 'hubble')
elif 'sunos5' in __PLATFORM:
    SHARE_DIR = os.path.join(ROOT_DIR, 'usr', 'share', 'hubble')
else:
    SHARE_DIR = os.path.join(ROOT_DIR, 'usr', 'share', 'hubble')

CACHE_DIR = os.path.join(ROOT_DIR, 'var', 'cache', 'hubble')
SOCK_DIR = os.path.join(ROOT_DIR, 'var', 'run', 'hubble')
SRV_ROOT_DIR = os.path.join(ROOT_DIR, 'srv')
BASE_FILE_ROOTS_DIR = os.path.join(SRV_ROOT_DIR, 'hubble')
LOGS_DIR = os.path.join(ROOT_DIR, 'var', 'log', 'hubble')
PIDFILE_DIR = os.path.join(ROOT_DIR, 'var', 'run')
HOME_DIR = os.path.expanduser('~')

__all__ = [
    'ROOT_DIR',
    'SHARE_DIR',
    'CONFIG_DIR',
    'CACHE_DIR',
    'SOCK_DIR',
    'SRV_ROOT_DIR',
    'BASE_FILE_ROOTS_DIR',
    'LOGS_DIR',
    'PIDFILE_DIR',
    'INSTALL_DIR',
]
