# -*- coding: utf-8 -*-
"""
Execute calls on selinux
"""
import os
import hubblestack.utils.files
import hubblestack.utils.stringutils
from hubblestack.utils.decorators.memoize import memoize


# Cache the SELinux directory to not look it up over and over
@memoize
def selinux_fs_path():
    """
    Return the location of the SELinux VFS directory
    CLI Example:
    .. code-block:: bash
        salt '*' selinux.selinux_fs_path
    """
    # systems running systemd (e.g. Fedora 15 and newer)
    # have the selinux filesystem in a different location
    try:
        for directory in ("/sys/fs/selinux", "/selinux"):
            if os.path.isdir(directory):
                if os.path.isfile(os.path.join(directory, "enforce")):
                    return directory
        return None
    # If selinux is Disabled, the path does not exist.
    except AttributeError:
        return None


def getenforce():
    """
    Return the mode selinux is running in
    CLI Example:
    .. code-block:: bash
        salt '*' selinux.getenforce
    """
    _selinux_fs_path = selinux_fs_path()
    if _selinux_fs_path is None:
        return "Disabled"
    try:
        enforce = os.path.join(_selinux_fs_path, "enforce")
        with hubblestack.utils.files.fopen(enforce, "r") as _fp:
            if hubblestack.utils.stringutils.to_unicode(_fp.readline()).strip() == "0":
                return "Permissive"
            else:
                return "Enforcing"
    except (IOError, OSError, AttributeError):
        return "Disabled"
