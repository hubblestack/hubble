# -*- coding: utf-8 -*-
'''
    :synopsis: Unit Tests for Advanced Packaging Tool module 'module.aptpkg'
    :platform: Linux
    :maturity: develop
    versionadded:: 2017.7.0
'''

# Import Python Libs
from __future__ import absolute_import, print_function, unicode_literals
import copy
import textwrap

from tests.support.mixins import LoaderModuleMockMixin
from tests.support.unit import TestCase, skipIf
from tests.support.mock import Mock, MagicMock, patch, NO_MOCK, NO_MOCK_REASON

from hubblestack.exceptions import CommandExecutionError, HubbleInvocationError
import hubblestack.modules.aptpkg as aptpkg

try:
    import pytest
except ImportError:
    pytest = None


APT_KEY_LIST = r'''
pub:-:1024:17:46181433FBB75451:1104433784:::-:::scSC:
fpr:::::::::C5986B4F1257FFA86632CBA746181433FBB75451:
uid:-::::1104433784::B4D41942D4B35FF44182C7F9D00C99AF27B93AD0::Ubuntu CD Image Automatic Signing Key <cdimage@ubuntu.com>:
'''

REPO_KEYS = {
    '46181433FBB75451': {
        'algorithm': 17,
        'bits': 1024,
        'capability': 'scSC',
        'date_creation': 1104433784,
        'date_expiration': None,
        'fingerprint': 'C5986B4F1257FFA86632CBA746181433FBB75451',
        'keyid': '46181433FBB75451',
        'uid': 'Ubuntu CD Image Automatic Signing Key <cdimage@ubuntu.com>',
        'uid_hash': 'B4D41942D4B35FF44182C7F9D00C99AF27B93AD0',
        'validity': '-'
    }
}

PACKAGES = {
    'wget': '1.15-1ubuntu1.14.04.2'
}

LOWPKG_FILES = {
    'errors': {},
    'packages': {
        'wget': [
            '/.',
            '/etc',
            '/etc/wgetrc',
            '/usr',
            '/usr/bin',
            '/usr/bin/wget',
            '/usr/share',
            '/usr/share/info',
            '/usr/share/info/wget.info.gz',
            '/usr/share/doc',
            '/usr/share/doc/wget',
            '/usr/share/doc/wget/MAILING-LIST',
            '/usr/share/doc/wget/NEWS.gz',
            '/usr/share/doc/wget/AUTHORS',
            '/usr/share/doc/wget/copyright',
            '/usr/share/doc/wget/changelog.Debian.gz',
            '/usr/share/doc/wget/README',
            '/usr/share/man',
            '/usr/share/man/man1',
            '/usr/share/man/man1/wget.1.gz',
        ]
    }
}

LOWPKG_INFO = {
    'wget': {
        'architecture': 'amd64',
        'description': 'retrieves files from the web',
        'homepage': 'http://www.gnu.org/software/wget/',
        'install_date': '2016-08-30T22:20:15Z',
        'maintainer': 'Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>',
        'name': 'wget',
        'section': 'web',
        'source': 'wget',
        'version': '1.15-1ubuntu1.14.04.2'
    }
}

APT_Q_UPDATE = '''
Get:1 http://security.ubuntu.com trusty-security InRelease [65 kB]
Get:2 http://security.ubuntu.com trusty-security/main Sources [120 kB]
Get:3 http://security.ubuntu.com trusty-security/main amd64 Packages [548 kB]
Get:4 http://security.ubuntu.com trusty-security/main i386 Packages [507 kB]
Hit http://security.ubuntu.com trusty-security/main Translation-en
Fetched 1240 kB in 10s (124 kB/s)
Reading package lists...
'''

APT_Q_UPDATE_ERROR = '''
Err http://security.ubuntu.com trusty InRelease

Err http://security.ubuntu.com trusty Release.gpg
Unable to connect to security.ubuntu.com:http:
Reading package lists...
W: Failed to fetch http://security.ubuntu.com/ubuntu/dists/trusty/InRelease

W: Failed to fetch http://security.ubuntu.com/ubuntu/dists/trusty/Release.gpg  Unable to connect to security.ubuntu.com:http:

W: Some index files failed to download. They have been ignored, or old ones used instead.
'''

AUTOREMOVE = '''
Reading package lists... Done
Building dependency tree
Reading state information... Done
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
'''

UPGRADE = '''
Reading package lists...
Building dependency tree...
Reading state information...
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
'''

UNINSTALL = {
    'tmux': {
        'new': str(),
        'old': '1.8-5'
    }
}


@skipIf(NO_MOCK, NO_MOCK_REASON)
class AptPkgTestCase(TestCase, LoaderModuleMockMixin):
    '''
    Test cases for hubblestack.modules.aptpkg
    '''

    def setup_loader_modules(self):
        return {aptpkg: {}}

    def test_version(self):
        '''
        Test - Returns a string representing the package version or an empty string if
        not installed.
        '''
        version = LOWPKG_INFO['wget']['version']
        mock = MagicMock(return_value=version)
        with patch.dict(aptpkg.__mods__, {'pkg_resource.version': mock}):
            self.assertEqual(aptpkg.version(*['wget']), version)

    def test_refresh_db(self):
        '''
        Test - Updates the APT database to latest packages based upon repositories.
        '''
        refresh_db = {
            'http://security.ubuntu.com trusty-security InRelease': True,
            'http://security.ubuntu.com trusty-security/main Sources': True,
            'http://security.ubuntu.com trusty-security/main Translation-en': None,
            'http://security.ubuntu.com trusty-security/main amd64 Packages': True,
            'http://security.ubuntu.com trusty-security/main i386 Packages': True
        }
        mock = MagicMock(return_value={
            'retcode': 0,
            'stdout': APT_Q_UPDATE
        })
        with patch('hubblestack.utils.pkg.clear_rtag', MagicMock()):
            with patch.dict(aptpkg.__mods__, {'cmd.run_all': mock, 'config.get': MagicMock(return_value=False)}):
                self.assertEqual(aptpkg.refresh_db(), refresh_db)

    def test_refresh_db_failed(self):
        '''
        Test - Update the APT database using unreachable repositories.
        '''
        kwargs = {'failhard': True}
        mock = MagicMock(return_value={
            'retcode': 0,
            'stdout': APT_Q_UPDATE_ERROR
        })
        with patch('hubblestack.utils.pkg.clear_rtag', MagicMock()):
            with patch.dict(aptpkg.__mods__, {'cmd.run_all': mock, 'config.get': MagicMock(return_value=False)}):
                self.assertRaises(CommandExecutionError, aptpkg.refresh_db, **kwargs)

@skipIf(pytest is None, 'PyTest is missing')
class AptUtilsTestCase(TestCase, LoaderModuleMockMixin):
    '''
    apt utils test case
    '''
    def setup_loader_modules(self):
        return {aptpkg: {}}

    def test_call_apt_default(self):
        '''
        Call default apt.
        :return:
        '''
        with patch.dict(aptpkg.__mods__, {'cmd.run_all': MagicMock(), 'config.get': MagicMock(return_value=False)}):
            aptpkg._call_apt(['apt-get', 'install', 'emacs'])  # pylint: disable=W0106
            aptpkg.__mods__['cmd.run_all'].assert_called_once_with(
                ['apt-get', 'install', 'emacs'], env={},
                output_loglevel='trace', python_shell=False)

    @patch('hubblestack.utils.systemd.has_scope', MagicMock(return_value=True))
    def test_call_apt_in_scope(self):
        '''
        Call apt within the scope.
        :return:
        '''
        with patch.dict(aptpkg.__mods__, {'cmd.run_all': MagicMock(), 'config.get': MagicMock(return_value=True)}):
            aptpkg._call_apt(['apt-get', 'purge', 'vim'])  # pylint: disable=W0106
            aptpkg.__mods__['cmd.run_all'].assert_called_once_with(
                ['systemd-run', '--scope', 'apt-get', 'purge', 'vim'], env={},
                output_loglevel='trace', python_shell=False)

    def test_call_apt_with_kwargs(self):
        '''
        Call apt with the optinal keyword arguments.
        :return:
        '''
        with patch.dict(aptpkg.__mods__, {'cmd.run_all': MagicMock(), 'config.get': MagicMock(return_value=False)}):
            aptpkg._call_apt(['dpkg', '-l', 'python'],
                             python_shell=True, output_loglevel='quiet', ignore_retcode=False,
                             username='Darth Vader')  # pylint: disable=W0106
            aptpkg.__mods__['cmd.run_all'].assert_called_once_with(
                ['dpkg', '-l', 'python'], env={}, ignore_retcode=False,
                output_loglevel='quiet', python_shell=True, username='Darth Vader')
