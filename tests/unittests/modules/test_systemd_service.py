# -*- coding: utf-8 -*-
'''
    :codeauthor: Rahul Handay <rahulha@saltstack.com>
'''

# Import Python libs
from __future__ import absolute_import, unicode_literals, print_function
import os

# Import Salt Testing Libs
from tests.support.mixins import LoaderModuleMockMixin
from tests.support.unit import TestCase, skipIf
from tests.support.mock import (
    MagicMock,
    patch,
    NO_MOCK,
    NO_MOCK_REASON
)

# Import Salt Libs
import hubblestack.modules.systemd_service as systemd
import hubblestack.utils.systemd
from hubblestack.exceptions import CommandExecutionError

_SYSTEMCTL_STATUS = {
    'sshd.service': {
        'stdout': '''\
* sshd.service - OpenSSH Daemon
   Loaded: loaded (/usr/lib/systemd/system/sshd.service; disabled; vendor preset: disabled)
   Active: inactive (dead)''',
        'stderr': '',
        'retcode': 3,
        'pid': 12345,
    },

    'foo.service': {
        'stdout': '''\
* foo.service
   Loaded: not-found (Reason: No such file or directory)
   Active: inactive (dead)''',
        'stderr': '',
        'retcode': 3,
        'pid': 12345,
    },
}

# This reflects systemd >= 231 behavior
_SYSTEMCTL_STATUS_GTE_231 = {
    'bar.service': {
        'stdout': 'Unit bar.service could not be found.',
        'stderr': '',
        'retcode': 4,
        'pid': 12345,
    },
}

_LIST_UNIT_FILES = '''\
service1.service                           enabled
service2.service                           disabled
service3.service                           static
timer1.timer                               enabled
timer2.timer                               disabled
timer3.timer                               static'''


@skipIf(NO_MOCK, NO_MOCK_REASON)
class SystemdTestCase(TestCase, LoaderModuleMockMixin):
    '''
    Test case for hubblestack.modules.systemd
    '''
    def setup_loader_modules(self):
        return {systemd: {}}

    def test_systemctl_reload(self):
        '''
            Test to Reloads systemctl
        '''
        mock = MagicMock(side_effect=[
            {'stdout': 'Who knows why?',
             'stderr': '',
             'retcode': 1,
             'pid': 12345},
            {'stdout': '',
             'stderr': '',
             'retcode': 0,
             'pid': 54321},
        ])
        with patch.dict(systemd.__mods__, {'cmd.run_all': mock}):
            self.assertRaisesRegex(
                CommandExecutionError,
                'Problem performing systemctl daemon-reload: Who knows why?',
                systemd.systemctl_reload
            )
            self.assertTrue(systemd.systemctl_reload())

    def test_get_all(self):
        '''
        Test to return a list of all available services
        '''
        listdir_mock = MagicMock(side_effect=[
            ['foo.service', 'multi-user.target.wants', 'mytimer.timer'],
            [],
            ['foo.service', 'multi-user.target.wants', 'bar.service'],
            ['mysql', 'nginx', 'README']
        ])
        access_mock = MagicMock(
            side_effect=lambda x, y: x != os.path.join(
                systemd.INITSCRIPT_PATH,
                'README'
            )
        )
        with patch.object(os, 'listdir', listdir_mock):
            with patch.object(os, 'access', side_effect=access_mock):
                self.assertListEqual(
                    systemd.get_all(),
                    ['bar', 'foo', 'mysql', 'mytimer.timer', 'nginx']
                )

    def test_available(self):
        '''
        Test to check that the given service is available
        '''
        mock = MagicMock(side_effect=lambda x: _SYSTEMCTL_STATUS[x])

        # systemd < 231
        with patch.dict(systemd.__context__, {'hubblestack.utils.systemd.version': 230}):
            with patch.object(systemd, '_systemctl_status', mock):
                self.assertTrue(systemd.available('sshd.service'))
                self.assertFalse(systemd.available('foo.service'))

        # systemd >= 231
        with patch.dict(systemd.__context__, {'hubblestack.utils.systemd.version': 231}):
            with patch.dict(_SYSTEMCTL_STATUS, _SYSTEMCTL_STATUS_GTE_231):
                with patch.object(systemd, '_systemctl_status', mock):
                    self.assertTrue(systemd.available('sshd.service'))
                    self.assertFalse(systemd.available('bar.service'))

        # systemd < 231 with retcode/output changes backported (e.g. RHEL 7.3)
        with patch.dict(systemd.__context__, {'hubblestack.utils.systemd.version': 219}):
            with patch.dict(_SYSTEMCTL_STATUS, _SYSTEMCTL_STATUS_GTE_231):
                with patch.object(systemd, '_systemctl_status', mock):
                    self.assertTrue(systemd.available('sshd.service'))
                    self.assertFalse(systemd.available('bar.service'))