# -*- coding: utf-8 -*-
"""
Module for managing Windows systems and getting Windows system information.
Support for reboot, shutdown, join domain, rename
:depends:
    - wmi
    -pywin32
"""
try:
    import wmi

    HAS_WIN32NET_MODS = True
except ImportError:
    HAS_WIN32NET_MODS = False

import hubblestack.utils.platform
import hubblestack.utils.winapi

# Define the module's virtual name
__virtualname__ = "system"


def __virtual__():
    """
    Only works on Windows Systems with Win32 Modules
    """
    if not hubblestack.utils.platform.is_windows():
        return False, "Module win_system: Requires Windows"

    if not HAS_WIN32NET_MODS:
        return False, "Module win_system: Missing win32 modules"

    return __virtualname__


def get_domain_workgroup():
    """
    Get the domain or workgroup the computer belongs to.
    .. versionadded:: 2015.5.7
    .. versionadded:: 2015.8.2
    Returns:
        str: The name of the domain or workgroup
    CLI Example:
    .. code-block:: bash
        salt 'minion-id' system.get_domain_workgroup
    """
    with hubblestack.utils.winapi.Com():
        conn = wmi.WMI()
        for computer in conn.Win32_ComputerSystem():
            if computer.PartOfDomain:
                return {"Domain": computer.Domain}
            else:
                return {"Workgroup": computer.Domain}
