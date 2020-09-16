# -*- coding: utf-8 -*-
"""
    :codeauthor: Rahul Handay <rahulha@saltstack.com>
"""
# Import Salt Libs
import hubblestack.modules.win_system as win_system
import hubblestack.utils.platform

# Import Salt Testing Libs
from tests.support.mixins import LoaderModuleMockMixin
from tests.support.mock import MagicMock, Mock, patch
from tests.support.unit import TestCase, skipIf

try:
    import wmi

    HAS_WMI = True
except ImportError:
    HAS_WMI = False


class MockWMI_ComputerSystem(object):
    """
    Mock WMI Win32_ComputerSystem Class
    """

    BootupState = "Normal boot"
    Caption = "SALT SERVER"
    ChassisBootupState = 3
    ChassisSKUNumber = "3.14159"
    DNSHostname = "SALT SERVER"
    Domain = "WORKGROUP"
    DomainRole = 2
    Manufacturer = "Dell Inc."
    Model = "Dell 2980"
    NetworkServerModeEnabled = True
    PartOfDomain = False
    PCSystemType = 4
    PowerState = 0
    Status = "OK"
    SystemType = "x64-based PC"
    TotalPhysicalMemory = 17078214656
    ThermalState = 3
    Workgroup = "WORKGROUP"

    def __init__(self):
        pass

    @staticmethod
    def Rename(Name):
        return Name == Name

    @staticmethod
    def JoinDomainOrWorkgroup(Name):
        return [0]

    @staticmethod
    def UnjoinDomainOrWorkgroup(Password, UserName, FUnjoinOptions):
        return [0]


@skipIf(not HAS_WMI, "WMI only available on Windows")
@skipIf(not hubblestack.utils.platform.is_windows(), "System is not Windows")
class WinSystemTestCase(TestCase, LoaderModuleMockMixin):
    """
        Test cases for hubblestack.modules.win_system
    """
    def test_get_domain_workgroup(self):
        """
        Test get_domain_workgroup
        """
        with patch.object(wmi, "WMI", Mock(return_value=self.WMI)), patch(
            "hubblestack.utils.winapi.Com", MagicMock()
        ), patch.object(
            self.WMI, "Win32_ComputerSystem", return_value=[MockWMI_ComputerSystem()]
        ):
            self.assertDictEqual(
                win_system.get_domain_workgroup(), {"Workgroup": "WORKGROUP"}
            )
