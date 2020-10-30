# -*- coding: utf-8 -*-
'''
    :codeauthor: Jayesh Kariya <jayeshk@saltstack.com>
'''

# Import Python Libs
from __future__ import absolute_import, unicode_literals, print_function

# Import Salt Testing Libs
from tests.support.mixins import LoaderModuleMockMixin
from tests.support.unit import TestCase, skipIf
from tests.support.mock import (
    MagicMock,
    patch,
    Mock,
    NO_MOCK,
    NO_MOCK_REASON
)

import hubblestack.modules.win_network as win_network

try:
    import wmi
    HAS_WMI = True
except ImportError:
    HAS_WMI = False


@skipIf(NO_MOCK, NO_MOCK_REASON)
class WinNetworkTestCase(TestCase, LoaderModuleMockMixin):
    '''
    Test cases for hubblestack.modules.win_network
    '''
    def setup_loader_modules(self):
        self.WMI = Mock()
        self.addCleanup(delattr, self, 'WMI')
        return {win_network: {}}

    # 'netstat' function tests: 1

    def test_netstat(self):
        '''
        Test if it return information on open ports and states
        '''
        ret = ('  Proto  Local Address    Foreign Address    State    PID\n'
               '  TCP    127.0.0.1:1434    0.0.0.0:0    LISTENING    1728\n'
               '  UDP    127.0.0.1:1900    *:*        4240')
        mock = MagicMock(return_value=ret)
        with patch.dict(win_network.__mods__, {'cmd.run': mock}):
            self.assertListEqual(win_network.netstat(),
                                 [{'local-address': '127.0.0.1:1434',
                                   'program': '1728', 'proto': 'TCP',
                                   'remote-address': '0.0.0.0:0',
                                   'state': 'LISTENING'},
                                  {'local-address': '127.0.0.1:1900',
                                   'program': '4240', 'proto': 'UDP',
                                   'remote-address': '*:*', 'state': None}])
