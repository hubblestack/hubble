# -*- coding: utf-8 -*-
'''
Various functions to be used by windows during start up and to monkey patch
missing functions in other modules
'''
import platform
import re
import ctypes

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


# Although utils are often directly imported, it is also possible to use the
# loader.
def __virtual__():
    '''
    Only load if Win32 Libraries are installed
    '''
    if not HAS_WIN32:
        return False, 'This utility requires pywin32'

    return 'win_functions'

def escape_argument(arg, escape=True):
    '''
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
    '''
    if not arg or re.search(r'(["\s])', arg):
        arg = '"' + arg.replace('"', r'\"') + '"'

    if not escape:
        return arg
    return escape_for_cmd_exe(arg)


def escape_for_cmd_exe(arg):
    '''
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
    '''
    meta_chars = '()%!^"<>&|'
    meta_re = re.compile('(' + '|'.join(re.escape(char) for char in list(meta_chars)) + ')')
    meta_map = {char: "^{0}".format(char) for char in meta_chars}

    def escape_meta_chars(m):
        char = m.group(1)
        return meta_map[char]

    return meta_re.sub(escape_meta_chars, arg)
