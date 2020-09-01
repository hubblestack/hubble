# -*- coding: utf-8 -*-
'''
    :codeauthor: Rahul Handay <rahulha@saltstack.com>
'''

# Import Python Libs
from __future__ import absolute_import, unicode_literals, print_function

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
import hubblestack.modules.win_service as win_service
import hubblestack.utils.path

# Import 3rd Party Libs
try:
    WINAPI = True
    import win32serviceutil
    import pywintypes
except ImportError:
    WINAPI = False


@skipIf(NO_MOCK, NO_MOCK_REASON)
class WinServiceTestCase(TestCase, LoaderModuleMockMixin):
    '''
        Test cases for salt.modules.win_service
    '''
    def setup_loader_modules(self):
        return {win_service: {}}

    def test_available(self):
        '''
            Test to Returns ``True`` if the specified service
            is available, otherwise returns ``False``
        '''
        mock = MagicMock(return_value=['c', 'a', 'b'])
        with patch.object(win_service, 'get_all', mock):
            self.assertTrue(win_service.available("a"))

    def test_get_all(self):
        '''
            Test to return all installed services
        '''
        mock = MagicMock(return_value=[{'ServiceName': 'spongebob'},
                                       {'ServiceName': 'squarepants'},
                                       {'ServiceName': 'patrick'}])
        with patch.object(win_service, '_get_services', mock):
            self.assertListEqual(win_service.get_all(),
                                 ['patrick', 'spongebob', 'squarepants'])

    def test_get_service_name(self):
        '''
            Test to the Display Name is what is displayed
            in Windows when services.msc is executed.
        '''
        mock = MagicMock(return_value=[{'ServiceName': 'spongebob',
                                        'DisplayName': 'Sponge Bob'},
                                       {'ServiceName': 'squarepants',
                                        'DisplayName': 'Square Pants'},
                                       {'ServiceName': 'patrick',
                                        'DisplayName': 'Patrick the Starfish'}])
        with patch.object(win_service, '_get_services', mock):
            self.assertDictEqual(win_service.get_service_name(),
                                 {'Patrick the Starfish': 'patrick',
                                  'Sponge Bob': 'spongebob',
                                  'Square Pants': 'squarepants'})
            self.assertDictEqual(win_service.get_service_name('patrick'),
                                 {'Patrick the Starfish': 'patrick'})

    @skipIf(not WINAPI, 'win32serviceutil not available')
    def test_status(self):
        '''
            Test to return the status for a service
        '''
        mock_info = MagicMock(side_effect=[{'Status': 'Running'},
                                           {'Status': 'Stop Pending'},
                                           {'Status': 'Stopped'}])

        with patch.object(win_service, 'info', mock_info):
            self.assertTrue(win_service.status('spongebob'))
            self.assertTrue(win_service.status('patrick'))
            self.assertFalse(win_service.status('squidward'))

    def test_enabled(self):
        '''
            Test to check to see if the named
            service is enabled to start on boot
        '''
        mock = MagicMock(side_effect=[{'StartType': 'Auto'},
                                      {'StartType': 'Disabled'}])
        with patch.object(win_service, 'info', mock):
            self.assertTrue(win_service.enabled('spongebob'))
            self.assertFalse(win_service.enabled('squarepants'))

    def test_enabled_with_space_in_name(self):
        '''
            Test to check to see if the named
            service is enabled to start on boot
            when have space in service name
        '''
        mock = MagicMock(side_effect=[{'StartType': 'Auto'},
                                      {'StartType': 'Disabled'}])
        with patch.object(win_service, 'info', mock):
            self.assertTrue(win_service.enabled('spongebob test'))
            self.assertFalse(win_service.enabled('squarepants test'))