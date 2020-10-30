# -*- coding: utf-8 -*-
"""
Various functions to be used by windows during start up and to monkey patch
missing functions in other modules
"""
import re

# Import 3rd Party Libs
try:
    import psutil
    import pywintypes
    import win32api
    import win32net
    import win32security
    from win32con import HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG

    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

from hubblestack.exceptions import CommandExecutionError


# Although utils are often directly imported, it is also possible to use the
# loader.
def __virtual__():
    """
    Only load if Win32 Libraries are installed
    """
    if not HAS_WIN32:
        return False, 'This utility requires pywin32'

    return 'win_functions'


def escape_argument(arg, escape=True):
    """
    Escape the argument for the cmd.exe shell.
    See http://blogs.msdn.com/b/twistylittlepassagesallalike/archive/2011/04/23/everyone-quotes-arguments-the-wrong-way.aspx

    First we escape the quote chars to produce a argument suitable for
    CommandLineToArgvW. We don't need to do this for simple arguments.

    Args:
        arg (str): a single command line argument to escape for the cmd.exe shell

    Kwargs:
        escape (bool): True will call the escape_for_cmd_exe() function
                       which escapes the characters '()%!^"<>&|'. False
                       will not call the function and only quotes the cmd

    Returns:
        str: an escaped string suitable to be passed as a program argument to the cmd.exe shell
    """
    if not arg or re.search(r'(["\s])', arg):
        arg = '"' + arg.replace('"', r'\"') + '"'

    if not escape:
        return arg
    return escape_for_cmd_exe(arg)


def escape_for_cmd_exe(arg):
    """
    Escape an argument string to be suitable to be passed to
    cmd.exe on Windows

    This method takes an argument that is expected to already be properly
    escaped for the receiving program to be properly parsed. This argument
    will be further escaped to pass the interpolation performed by cmd.exe
    unchanged.

    Any meta-characters will be escaped, removing the ability to e.g. use
    redirects or variables.

    Args:
        arg (str): a single command line argument to escape for cmd.exe

    Returns:
        str: an escaped string suitable to be passed as a program argument to cmd.exe
    """
    meta_chars = '()%!^"<>&|'
    meta_re = re.compile('(' + '|'.join(re.escape(char) for char in list(meta_chars)) + ')')
    meta_map = {char: "^{0}".format(char) for char in meta_chars}

    def escape_meta_chars(m):
        char = m.group(1)
        return meta_map[char]

    return meta_re.sub(escape_meta_chars, arg)


def guid_to_squid(guid):
    """
    Converts a GUID   to a compressed guid (SQUID)

    Each Guid has 5 parts separated by '-'. For the first three each one will be
    totally reversed, and for the remaining two each one will be reversed by
    every other character. Then the final compressed Guid will be constructed by
    concatenating all the reversed parts without '-'.

    .. Example::

        Input:                  2BE0FA87-5B36-43CF-95C8-C68D6673FB94
        Reversed:               78AF0EB2-63B5-FC34-598C-6CD86637BF49
        Final Compressed Guid:  78AF0EB263B5FC34598C6CD86637BF49

    Args:

        guid (str): A valid GUID

    Returns:
        str: A valid compressed GUID (SQUID)
    """
    guid_pattern = re.compile(r'^\{(\w{8})-(\w{4})-(\w{4})-(\w\w)(\w\w)-(\w\w)(\w\w)(\w\w)(\w\w)(\w\w)(\w\w)\}$')
    guid_match = guid_pattern.match(guid)
    squid = ''
    if guid_match is not None:
        for index in range(1, 12):
            squid += guid_match.group(index)[::-1]
    return squid


def get_sid_from_name(name):
    """
    This is a tool for getting a sid from a name. The name can be any object.
    Usually a user or a group

    Args:
        name (str): The name of the user or group for which to get the sid

    Returns:
        str: The corresponding SID
    """
    # If None is passed, use the Universal Well-known SID "Null SID"
    if name is None:
        name = "NULL SID"

    try:
        sid = win32security.LookupAccountName(None, name)[0]
    except pywintypes.error as exc:
        raise CommandExecutionError("User {0} not found: {1}".format(name, exc))

    return win32security.ConvertSidToStringSid(sid)


def get_current_user(with_domain=True):
    """
    Gets the user executing the process

    Args:

        with_domain (bool):
            ``True`` will prepend the user name with the machine name or domain
            separated by a backslash

    Returns:
        str: The user name
    """
    try:
        user_name = win32api.GetUserNameEx(win32api.NameSamCompatible)
        if user_name[-1] == "$":
            # Make the system account easier to identify.
            # Fetch sid so as to handle other language than english
            test_user = win32api.GetUserName()
            if test_user == "SYSTEM":
                user_name = "SYSTEM"
            elif get_sid_from_name(test_user) == "S-1-5-18":
                user_name = "SYSTEM"
        elif not with_domain:
            user_name = win32api.GetUserName()
    except pywintypes.error as exc:
        raise CommandExecutionError("Failed to get current user: {0}".format(exc))

    if not user_name:
        return False

    return user_name
