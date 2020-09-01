# -*- coding: utf-8 -*-
'''
    :codeauthor: Jayesh Kariya <jayeshk@saltstack.com>
'''
import os

from tests.support.mixins import LoaderModuleMockMixin
from tests.support.unit import skipIf, TestCase
from tests.support.mock import (
    NO_MOCK,
    NO_MOCK_REASON,
    MagicMock,
    patch)

# Import Salt Libs
import hubblestack.modules.service as service


@skipIf(NO_MOCK, NO_MOCK_REASON)
class ServiceTestCase(TestCase, LoaderModuleMockMixin):
    '''
    Test cases for hubblestack.modules.service
    '''
    def setup_loader_modules(self):
        return {service: {}}

    def test_status(self):
        '''
        Test to return the status for a service, returns the PID or an empty
        string if the service is running or not, pass a signature to use to
        find the service via ps
        '''
        with patch.dict(service.__salt__,
                        {'status.pid': MagicMock(return_value=True)}):
            self.assertTrue(service.status('name'))

    def test_available(self):
        '''
        Test to returns ``True`` if the specified service is available,
        otherwise returns ``False``.
        '''
        with patch.object(service, 'get_all', return_value=['name', 'A']):
            self.assertTrue(service.available('name'))

    def test_get_all(self):
        '''
        Test to return a list of all available services
        '''
        with patch.object(os.path, 'isdir', side_effect=[False, True]):

            self.assertEqual(service.get_all(), [])

            with patch.object(os, 'listdir', return_value=['A', 'B']):
                self.assertListEqual(service.get_all(), ['A', 'B'])
