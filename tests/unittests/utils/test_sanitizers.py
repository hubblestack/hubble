# -*- coding: utf-8 -*-

# Import python libs
from __future__ import absolute_import, print_function, unicode_literals

# Import Salt Libs
from hubblestack.utils.sanitizers import mask_args_value

# Import Salt Testing Libs
from tests.support.unit import TestCase, skipIf
from tests.support.mock import NO_MOCK, NO_MOCK_REASON


@skipIf(NO_MOCK, NO_MOCK_REASON)
class SanitizersTestCase(TestCase):
    def test_value_masked(self):
        '''
        Test if the values are masked.
        :return:
        '''
        out = mask_args_value('quantum: fluctuations', 'quant*')
        assert out == 'quantum: ** hidden **'

    def test_value_not_masked(self):
        '''
        Test if the values are not masked.
        :return:
        '''
        out = mask_args_value('quantum fluctuations', 'quant*')
        assert out == 'quantum fluctuations'
