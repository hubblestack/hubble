# -*- coding: utf-8 -*-
r"""
Manage the Windows registry

Hives
-----
Hives are the main sections of the registry and all begin with the word HKEY.

- HKEY_LOCAL_MACHINE
- HKEY_CURRENT_USER
- HKEY_USER


Keys
----
Keys are the folders in the registry. Keys can have many nested subkeys. Keys
can have a value assigned to them under the (Default)

When passing a key on the CLI it must be quoted correctly depending on the
backslashes being used (``\`` vs ``\\``). The following are valid methods of
passing the key on the CLI:

Using single backslashes:
    ``"SOFTWARE\Python"``
    ``'SOFTWARE\Python'`` (will not work on a Windows Master)

Using double backslashes:
    ``SOFTWARE\\Python``

-----------------
Values or Entries
-----------------

Values or Entries are the name/data pairs beneath the keys and subkeys. All keys
have a default name/data pair. The name is ``(Default)`` with a displayed value
of ``(value not set)``. The actual value is Null.

Example
-------

The following example is an export from the Windows startup portion of the
registry:

.. code-block:: bash

    [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
    "RTHDVCPL"="\"C:\\Program Files\\Realtek\\Audio\\HDA\\RtkNGUI64.exe\" -s"
    "NvBackend"="\"C:\\Program Files (x86)\\NVIDIA Corporation\\Update Core\\NvBackend.exe\""
    "BTMTrayAgent"="rundll32.exe \"C:\\Program Files (x86)\\Intel\\Bluetooth\\btmshellex.dll\",TrayApp"

In this example these are the values for each:

Hive:
    ``HKEY_LOCAL_MACHINE``

Key and subkeys:
    ``SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run``

Value:
    - There are 3 value names:
        - `RTHDVCPL`
        - `NvBackend`
        - `BTMTrayAgent`
    - Each value name has a corresponding value

:depends:   - hubblestack.utils.win_reg
"""
# When production windows installer is using Python 3, Python 2 code can be removed

# Import python libs
import logging

# Import Hubble libs
import hubblestack.utils.platform

log = logging.getLogger(__name__)

# Define the module's virtual name
__virtualname__ = "reg"


def __virtual__():
    """
    Only works on Windows systems with PyWin32
    """
    if not hubblestack.utils.platform.is_windows():
        return (
            False,
            "reg execution module failed to load: "
            "The module will only run on Windows systems",
        )

    if "reg.read_value" not in __utils__:
        return (
            False,
            "reg execution module failed to load: The reg hubblestack util is unavailable",
        )

    return __virtualname__


def read_value(hive, key, vname=None, use_32bit_registry=False):
    r"""
    Reads a registry value entry or the default value for a key. To read the
    default value, don't pass ``vname``

    Args:

        hive (str): The name of the hive. Can be one of the following:

            - HKEY_LOCAL_MACHINE or HKLM
            - HKEY_CURRENT_USER or HKCU
            - HKEY_USER or HKU
            - HKEY_CLASSES_ROOT or HKCR
            - HKEY_CURRENT_CONFIG or HKCC

        key (str):
            The key (looks like a path) to the value name.

        vname (str):
            The value name. These are the individual name/data pairs under the
            key. If not passed, the key (Default) value will be returned.

        use_32bit_registry (bool):
            Accesses the 32bit portion of the registry on 64bit installations.
            On 32bit machines this is ignored.

    Returns:
        dict: A dictionary containing the passed settings as well as the
        value_data if successful. If unsuccessful, sets success to False.

        bool: Returns False if the key is not found

        If vname is not passed:

            - Returns the first unnamed value (Default) as a string.
            - Returns none if first unnamed value is empty.

    CLI Example:

        The following will get the value of the ``version`` value name in the
        ``HKEY_LOCAL_MACHINE\\SOFTWARE\\Salt`` key

        .. code-block:: bash

            salt '*' reg.read_value HKEY_LOCAL_MACHINE 'SOFTWARE\Salt' 'version'

    CLI Example:

        The following will get the default value of the
        ``HKEY_LOCAL_MACHINE\\SOFTWARE\\Salt`` key

        .. code-block:: bash

            salt '*' reg.read_value HKEY_LOCAL_MACHINE 'SOFTWARE\Salt'
    """
    return __utils__["reg.read_value"](
        hive=hive, key=key, vname=vname, use_32bit_registry=use_32bit_registry
    )
