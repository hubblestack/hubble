# -*- coding: utf-8 -*-
'''
    Unit tests for hubblestack.utils.yamlloader
'''

# Import python libs
from __future__ import absolute_import, print_function, unicode_literals
import collections
import textwrap 

from yaml.constructor import ConstructorError
from hubblestack.utils.yamlloader import SaltYamlSafeLoader
import hubblestack.utils.files

# Import Testing Libs
from tests.support.unit import TestCase, skipIf
from tests.support.mock import patch, NO_MOCK, NO_MOCK_REASON, mock_open

@skipIf(NO_MOCK, NO_MOCK_REASON)
class YamlLoaderTestCase(TestCase):
    '''
    TestCase for hubblestack.utils.yamlloader module
    '''

    @staticmethod
    def render_yaml(data):
        '''
        Takes a YAML string, puts it into a mock file, passes that to the YAML
        SaltYamlSafeLoader and then returns the rendered/parsed YAML data
        '''
        with patch('hubblestack.utils.files.fopen', mock_open(read_data=data)) as mocked_file:
            with hubblestack.utils.files.fopen(mocked_file) as mocked_stream:
                return SaltYamlSafeLoader(mocked_stream).get_data()

    @staticmethod
    def raise_error(value):
        raise TypeError('{0!r} is not a unicode string'.format(value))  # pylint: disable=repr-flag-used-in-string

    def assert_matches(self, ret, expected):
        self.assertEqual(ret, expected)
        self.assert_unicode(ret)

    def test_yaml_duplicates(self):
        '''
        Test that duplicates still throw an error
        '''
        with self.assertRaises(ConstructorError):
            self.render_yaml(textwrap.dedent('''\
                p1: alpha
                p1: beta'''))

        with self.assertRaises(ConstructorError):
            self.render_yaml(textwrap.dedent('''\
                p1: &p1
                  v1: alpha
                p2:
                  <<: *p1
                  v2: beta
                  v2: betabeta'''))

