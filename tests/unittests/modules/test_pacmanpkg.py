# -*- coding: utf-8 -*-
'''
    :codeauthor: Eric Vz <eric@base10.org>
'''

from tests.support.mixins import LoaderModuleMockMixin
from tests.support.unit import TestCase, skipIf
from tests.support.mock import (
    MagicMock,
    patch,
    NO_MOCK,
    NO_MOCK_REASON
)

import hubblestack.modules.pacmanpkg as pacman


@skipIf(NO_MOCK, NO_MOCK_REASON)
class PacmanTestCase(TestCase, LoaderModuleMockMixin):
    '''
    Test cases for hubblestack.modules.pacman
    '''
    def setup_loader_modules(self):
        return {pacman: {}}

    def test_list_pkgs(self):
        '''
        Test if it list the packages currently installed in a dict
        '''
        cmdmock = MagicMock(return_value='A 1.0\nB 2.0')
        sortmock = MagicMock()
        stringifymock = MagicMock()
        mock_ret = {'A': ['1.0'], 'B': ['2.0']}
        with patch.dict(pacman.__mods__, {
                'cmd.run': cmdmock,
                'pkg_resource.add_pkg': lambda pkgs, name, version: pkgs.setdefault(name, []).append(version),
                'pkg_resource.sort_pkglist': sortmock,
                'pkg_resource.stringify': stringifymock
                }):
            self.assertDictEqual(pacman.list_pkgs(), mock_ret)

        sortmock.assert_called_with(mock_ret)
        stringifymock.assert_called_with(mock_ret)

    def test_list_pkgs_as_list(self):
        '''
        Test if it lists the packages currently installed in a dict
        '''
        cmdmock = MagicMock(return_value='A 1.0\nB 2.0')
        sortmock = MagicMock()
        stringifymock = MagicMock()
        mock_ret = {'A': ['1.0'], 'B': ['2.0']}
        with patch.dict(pacman.__mods__, {
                'cmd.run': cmdmock,
                'pkg_resource.add_pkg': lambda pkgs, name, version: pkgs.setdefault(name, []).append(version),
                'pkg_resource.sort_pkglist': sortmock,
                'pkg_resource.stringify': stringifymock
                }):
            self.assertDictEqual(pacman.list_pkgs(True), mock_ret)

        sortmock.assert_called_with(mock_ret)
        self.assertTrue(stringifymock.call_count == 0)

    
