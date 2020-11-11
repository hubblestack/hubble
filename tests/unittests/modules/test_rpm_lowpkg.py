# -*- coding: utf-8 -*-
'''
    :codeauthor: Jayesh Kariya <jayeshk@saltstack.com>
'''

# Import Python Libs
from __future__ import absolute_import

from tests.support.mixins import LoaderModuleMockMixin
from tests.support.unit import TestCase, skipIf
from tests.support.mock import (
    MagicMock,
    patch,
    NO_MOCK,
    NO_MOCK_REASON
)

import hubblestack.modules.rpm_lowpkg as rpm


@skipIf(NO_MOCK, NO_MOCK_REASON)
class RpmTestCase(TestCase, LoaderModuleMockMixin):
    '''
    Test cases for hubblestack.modules.rpm
    '''
    def setup_loader_modules(self):
        return {rpm: {'rpm': MagicMock(return_value=MagicMock)}}

    def test_version_cmp_rpm(self):
        '''
        Test package version is called RPM version if RPM-Python is installed

        :return:
        '''
        with patch('hubblestack.modules.rpm_lowpkg.rpm.labelCompare', MagicMock(return_value=0)), \
                patch('hubblestack.modules.rpm_lowpkg.HAS_RPM', True):
            self.assertEqual(0, rpm.version_cmp('1', '2'))  # mock returns 0, which means RPM was called

    def test_version_cmp_fallback(self):
        '''
        Test package version is called RPM version if RPM-Python is installed

        :return:
        '''
        with patch('hubblestack.modules.rpm_lowpkg.rpm.labelCompare', MagicMock(return_value=0)), \
                patch('hubblestack.modules.rpm_lowpkg.HAS_RPM', False):
            self.assertEqual(-1, rpm.version_cmp('1', '2'))  # mock returns -1, a python implementation was called
