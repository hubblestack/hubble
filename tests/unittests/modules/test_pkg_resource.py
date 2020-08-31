# -*- coding: utf-8 -*-
'''
    :codeauthor: Rahul Handay <rahulha@saltstack.com>
'''

# Import Python Libs
from __future__ import absolute_import, print_function, unicode_literals
import yaml

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
import hubblestack.utils.data
import hubblestack.utils.yaml
import hubblestack.modules.pkg_resource as pkg_resource


@skipIf(NO_MOCK, NO_MOCK_REASON)
class PkgresTestCase(TestCase, LoaderModuleMockMixin):
    '''
    Test cases for hubblestack.modules.pkg_resource
    '''
    def setup_loader_modules(self):
        return {pkg_resource: {}}

    def test_version(self):
        '''
            Test to Common interface for obtaining the version
            of installed packages.
        '''
        with patch.object(hubblestack.utils.data, 'is_true', return_value=True):
            mock = MagicMock(return_value={'A': 'B'})
            with patch.dict(pkg_resource.__salt__,
                            {'pkg.list_pkgs': mock}):
                self.assertEqual(pkg_resource.version('A'), 'B')

                self.assertDictEqual(pkg_resource.version(), {})

            mock = MagicMock(return_value={})
            with patch.dict(pkg_resource.__salt__, {'pkg.list_pkgs': mock}):
                with patch('builtins.next') as mock_next:
                    mock_next.side_effect = StopIteration()
                    self.assertEqual(pkg_resource.version('A'), '')

    def test_add_pkg(self):
        '''
            Test to add a package to a dict of installed packages.
        '''
        self.assertIsNone(pkg_resource.add_pkg({'pkgs': []}, 'name', 'version'))

    def test_sort_pkglist(self):
        '''
            Test to accepts a dict obtained from pkg.list_pkgs() and sorts
            in place the list of versions for any packages that have multiple
            versions installed, so that two package lists can be compared
            to one another.
        '''
        self.assertIsNone(pkg_resource.sort_pkglist({}))

    def test_stringify(self):
        '''
            Test to takes a dict of package name/version information
            and joins each list of
            installed versions into a string.
        '''
        self.assertIsNone(pkg_resource.stringify({}))
