# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function, unicode_literals

import hubblestack.modules.reg as reg
import hubblestack.utils.win_reg
from hubblestack.utils.exceptions import CommandExecutionError
from tests.support.helpers import random_string
from tests.support.mixins import LoaderModuleMockMixin
from tests.support.mock import MagicMock, patch
from tests.support.unit import TestCase, skipIf

try:
    import win32api

    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

UNICODE_KEY = "Unicode Key \N{TRADE MARK SIGN}"
UNICODE_VALUE = (
    "Unicode Value " "\N{COPYRIGHT SIGN},\N{TRADE MARK SIGN},\N{REGISTERED SIGN}"
)
FAKE_KEY = "SOFTWARE\\{}".format(random_string("SaltTesting-", lowercase=False))


@skipIf(not HAS_WIN32, "Tests require win32 libraries")
class WinFunctionsTestCase(TestCase, LoaderModuleMockMixin):
    """
    Test cases for salt.modules.reg
    """

    def setup_loader_modules(self):
        return {
            reg: {
                "__utils__": {
                    "reg.read_value": hubblestack.utils.win_reg.read_value,
                }
            }
        }

    def test_read_value_existing(self):
        """
        Test the read_value function using a well known registry value
        """
        ret = reg.read_value(
            hive="HKLM",
            key="SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
            vname="ProgramFilesPath",
        )
        self.assertEqual(ret["vdata"], "%ProgramFiles%")

    def test_read_value_default(self):
        """
        Test the read_value function reading the default value using a well
        known registry key
        """
        ret = reg.read_value(
            hive="HKLM", key="SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        )
        self.assertEqual(ret["vdata"], "(value not set)")

    def test_read_value_non_existing(self):
        """
        Test the read_value function using a non existing value pair
        """
        expected = {
            "comment": "Cannot find fake_name in HKLM\\SOFTWARE\\Microsoft\\"
            "Windows\\CurrentVersion",
            "vdata": None,
            "vname": "fake_name",
            "success": False,
            "hive": "HKLM",
            "key": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
        }
        self.assertDictEqual(
            reg.read_value(
                hive="HKLM",
                key="SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
                vname="fake_name",
            ),
            expected,
        )

    def test_read_value_non_existing_key(self):
        """
        Test the read_value function using a non existing registry key
        """
        expected = {
            "comment": "Cannot find key: HKLM\\{0}".format(FAKE_KEY),
            "vdata": None,
            "vname": "fake_name",
            "success": False,
            "hive": "HKLM",
            "key": FAKE_KEY,
        }
        self.assertDictEqual(
            reg.read_value(hive="HKLM", key=FAKE_KEY, vname="fake_name"), expected
        )

    def test_read_value_invalid_hive(self):
        """
        Test the read_value function when passing an invalid hive
        """
        self.assertRaises(
            CommandExecutionError,
            reg.read_value,
            hive="BADHIVE",
            key="SOFTWARE\\Microsoft",
            vname="ProgramFilesPath",
        )

    def test_read_value_unknown_key_error(self):
        """
        Tests the read_value function with an unknown key error
        """
        mock_error = MagicMock(
            side_effect=win32api.error(123, "RegOpenKeyEx", "Unknown error")
        )
        with patch("salt.utils.win_reg.win32api.RegOpenKeyEx", mock_error):
            self.assertRaises(
                win32api.error,
                reg.read_value,
                hive="HKLM",
                key="SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
                vname="ProgramFilesPath",
            )

    def test_read_value_unknown_value_error(self):
        """
        Tests the read_value function with an unknown value error
        """
        mock_error = MagicMock(
            side_effect=win32api.error(123, "RegQueryValueEx", "Unknown error")
        )
        with patch("salt.utils.win_reg.win32api.RegQueryValueEx", mock_error):
            self.assertRaises(
                win32api.error,
                reg.read_value,
                hive="HKLM",
                key="SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
                vname="ProgramFilesPath",
            )
