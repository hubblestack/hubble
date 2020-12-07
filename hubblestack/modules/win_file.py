# -*- coding: utf-8 -*-
"""
Manage information about files on the minion, set/read user, group
data, modify the ACL of files/directories

:depends:   - win32api
            - win32file
            - win32con
            - hubblestack.utils.win_dacl
"""
# pylint: disable=unused-import
import contextlib  # do not remove, used in imported file.py functions
import datetime  # do not remove.
import difflib  # do not remove, used in imported file.py functions
import errno  # do not remove, used in imported file.py functions
import fnmatch  # do not remove, used in imported file.py functions
import glob  # do not remove, used in imported file.py functions
import hashlib  # do not remove, used in imported file.py functions
import io  # do not remove, used in imported file.py functions
import logging
import mmap  # do not remove, used in imported file.py functions
import operator  # do not remove

# Import python libs
import os
import os.path
import re  # do not remove, used in imported file.py functions
import shutil  # do not remove, used in imported file.py functions
import stat
import string  # do not remove, used in imported file.py functions
import sys  # do not remove, used in imported file.py functions
from functools import reduce  # do not remove
import hubblestack.utils.files
import hubblestack.utils.path
import hubblestack.utils.platform
from hubblestack.utils.functools import namespaced_function as _namespaced_function
from hubblestack.exceptions import CommandExecutionError, HubbleInvocationError

from hubblestack.modules.file import (
    get_hash,
    get_sum,
)

from hubblestack.modules.file import (
    touch,
)

HAS_WINDOWS_MODULES = False
try:
    if hubblestack.utils.platform.is_windows():
        import win32api
        import win32con
        HAS_WINDOWS_MODULES = True
except ImportError:
    HAS_WINDOWS_MODULES = False

# This is to fix the pylint error: E0602: Undefined variable "WindowsError"
try:
    from exceptions import WindowsError  # pylint: disable=no-name-in-module
except ImportError:

    class WindowsError(OSError):
        pass


HAS_WIN_DACL = False
try:
    if hubblestack.utils.platform.is_windows():
        import hubblestack.utils.win_dacl
        HAS_WIN_DACL = True
except ImportError:
    HAS_WIN_DACL = False


log = logging.getLogger(__name__)

# Define the module's virtual name
__virtualname__ = "file"


def __virtual__():
    """
    Only works on Windows systems
    """
    if hubblestack.utils.platform.is_windows():
        if HAS_WINDOWS_MODULES:
            # Load functions from file.py
            global touch
            global get_sum, get_hash

            touch = _namespaced_function(touch, globals())
            get_sum = _namespaced_function(get_sum, globals())
            get_hash = _namespaced_function(get_hash, globals())
        else:
            return False, "Module win_file: Missing Win32 modules"

    if not HAS_WIN_DACL:
        return False, "Module win_file: Unable to load hubblestack.utils.win_dacl"

    return __virtualname__


__outputter__ = {
    "touch": "txt",
}


def _resolve_symlink(path, max_depth=64):
    """
    Resolves the given symlink path to its real path, up to a maximum of the
    `max_depth` parameter which defaults to 64.

    If the path is not a symlink path, it is simply returned.
    """
    if sys.getwindowsversion().major < 6:
        raise HubbleInvocationError(
            "Symlinks are only supported on Windows Vista or later."
        )

    # make sure we don't get stuck in a symlink loop!
    paths_seen = set((path,))
    cur_depth = 0
    while is_link(path):
        path = readlink(path)
        if path in paths_seen:
            raise CommandExecutionError("The given path is involved in a symlink loop.")
        paths_seen.add(path)
        cur_depth += 1
        if cur_depth > max_depth:
            raise CommandExecutionError("Too many levels of symbolic links.")

    return path


def gid_to_group(gid):
    """
    Convert the group id to the group name on this system

    Under Windows, because groups are just another ACL entity, this function
    behaves the same as uid_to_user.

    For maintaining Windows systems, this function is superfluous and only
    exists for API compatibility with Unix. Use the uid_to_user function
    instead; an info level log entry will be generated if this function is used
    directly.

    Args:
        gid (str): The gid of the group

    Returns:
        str: The name of the group

    CLI Example:

    .. code-block:: bash

        salt '*' file.gid_to_group S-1-5-21-626487655-2533044672-482107328-1010
    """
    func_name = "{0}.gid_to_group".format(__virtualname__)
    if __opts__.get("fun", "") == func_name:
        log.info(
            "The function %s should not be used on Windows systems; "
            "see function docs for details.",
            func_name,
        )

    return uid_to_user(gid)


def get_pgid(path, follow_symlinks=True):
    """
    Return the id of the primary group that owns a given file (Windows only)

    This function will return the rarely used primary group of a file. This
    generally has no bearing on permissions unless intentionally configured
    and is most commonly used to provide Unix compatibility (e.g. Services
    For Unix, NFS services).

    Ensure you know what you are doing before using this function.

    Args:
        path (str): The path to the file or directory

        follow_symlinks (bool):
            If the object specified by ``path`` is a symlink, get attributes of
            the linked file instead of the symlink itself. Default is True

    Returns:
        str: The gid of the primary group

    CLI Example:

    .. code-block:: bash

        salt '*' file.get_pgid c:\\temp\\test.txt
    """
    if not os.path.exists(path):
        raise CommandExecutionError("Path not found: {0}".format(path))

    # Under Windows, if the path is a symlink, the user that owns the symlink is
    # returned, not the user that owns the file/directory the symlink is
    # pointing to. This behavior is *different* to *nix, therefore the symlink
    # is first resolved manually if necessary. Remember symlinks are only
    # supported on Windows Vista or later.
    if follow_symlinks and sys.getwindowsversion().major >= 6:
        path = _resolve_symlink(path)

    group_name = hubblestack.utils.win_dacl.get_primary_group(path)
    return hubblestack.utils.win_dacl.get_sid_string(group_name)


def uid_to_user(uid):
    """
    Convert a uid to a user name

    Args:
        uid (str): The user id to lookup

    Returns:
        str: The name of the user

    CLI Example:

    .. code-block:: bash

        salt '*' file.uid_to_user S-1-5-21-626487655-2533044672-482107328-1010
    """
    if uid is None or uid == "":
        return ""

    return hubblestack.utils.win_dacl.get_name(uid)


def get_uid(path, follow_symlinks=True):
    """
    Return the id of the user that owns a given file

    Symlinks are followed by default to mimic Unix behavior. Specify
    `follow_symlinks=False` to turn off this behavior.

    Args:
        path (str): The path to the file or directory

        follow_symlinks (bool):
            If the object specified by ``path`` is a symlink, get attributes of
            the linked file instead of the symlink itself. Default is True

    Returns:
        str: The uid of the owner


    CLI Example:

    .. code-block:: bash

        salt '*' file.get_uid c:\\temp\\test.txt
        salt '*' file.get_uid c:\\temp\\test.txt follow_symlinks=False
    """
    if not os.path.exists(path):
        raise CommandExecutionError("Path not found: {0}".format(path))

    # Under Windows, if the path is a symlink, the user that owns the symlink is
    # returned, not the user that owns the file/directory the symlink is
    # pointing to. This behavior is *different* to *nix, therefore the symlink
    # is first resolved manually if necessary. Remember symlinks are only
    # supported on Windows Vista or later.
    if follow_symlinks and sys.getwindowsversion().major >= 6:
        path = _resolve_symlink(path)

    owner_sid = hubblestack.utils.win_dacl.get_owner(path)
    return hubblestack.utils.win_dacl.get_sid_string(owner_sid)


def stats(path, hash_type="sha256", follow_symlinks=True):
    """
    Return a dict containing the stats about a given file

    Under Windows, `gid` will equal `uid` and `group` will equal `user`.

    While a file in Windows does have a 'primary group', this rarely used
    attribute generally has no bearing on permissions unless intentionally
    configured and is only used to support Unix compatibility features (e.g.
    Services For Unix, NFS services).

    Salt, therefore, remaps these properties to keep some kind of
    compatibility with Unix behavior. If the 'primary group' is required, it
    can be accessed in the `pgroup` and `pgid` properties.

    Args:
        path (str): The path to the file or directory
        hash_type (str): The type of hash to return
        follow_symlinks (bool):
            If the object specified by ``path`` is a symlink, get attributes of
            the linked file instead of the symlink itself. Default is True

    Returns:
        dict: A dictionary of file/directory stats

    CLI Example:

    .. code-block:: bash

        salt '*' file.stats /etc/passwd
    """
    # This is to mirror the behavior of file.py. `check_file_meta` expects an
    # empty dictionary when the file does not exist
    if not os.path.exists(path):
        raise CommandExecutionError("Path not found: {0}".format(path))

    if follow_symlinks and sys.getwindowsversion().major >= 6:
        path = _resolve_symlink(path)

    pstat = os.stat(path)

    ret = {}
    ret["inode"] = pstat.st_ino
    # don't need to resolve symlinks again because we've already done that
    ret["uid"] = get_uid(path, follow_symlinks=False)
    # maintain the illusion that group is the same as user as states need this
    ret["gid"] = ret["uid"]
    ret["user"] = uid_to_user(ret["uid"])
    ret["group"] = ret["user"]
    ret["pgid"] = get_pgid(path, follow_symlinks)
    ret["pgroup"] = gid_to_group(ret["pgid"])
    ret["atime"] = pstat.st_atime
    ret["mtime"] = pstat.st_mtime
    ret["ctime"] = pstat.st_ctime
    ret["size"] = pstat.st_size
    ret["mode"] = hubblestack.utils.files.normalize_mode(oct(stat.S_IMODE(pstat.st_mode)))
    if hash_type:
        ret["sum"] = get_sum(path, hash_type)
    ret["type"] = "file"
    if stat.S_ISDIR(pstat.st_mode):
        ret["type"] = "dir"
    if stat.S_ISCHR(pstat.st_mode):
        ret["type"] = "char"
    if stat.S_ISBLK(pstat.st_mode):
        ret["type"] = "block"
    if stat.S_ISREG(pstat.st_mode):
        ret["type"] = "file"
    if stat.S_ISLNK(pstat.st_mode):
        ret["type"] = "link"
    if stat.S_ISFIFO(pstat.st_mode):
        ret["type"] = "pipe"
    if stat.S_ISSOCK(pstat.st_mode):
        ret["type"] = "socket"
    ret["target"] = os.path.realpath(path)
    return ret


def remove(path, force=False):
    """
    Remove the named file or directory

    Args:
        path (str): The path to the file or directory to remove.
        force (bool): Remove even if marked Read-Only. Default is False

    Returns:
        bool: True if successful, False if unsuccessful

    CLI Example:

    .. code-block:: bash

        salt '*' file.remove C:\\Temp
    """
    # This must be a recursive function in windows to properly deal with
    # Symlinks. The shutil.rmtree function will remove the contents of
    # the Symlink source in windows.

    path = os.path.expanduser(path)

    if not os.path.isabs(path):
        raise HubbleInvocationError("File path must be absolute: {0}".format(path))

    # Does the file/folder exists
    if not os.path.exists(path) and not is_link(path):
        raise CommandExecutionError("Path not found: {0}".format(path))

    # Remove ReadOnly Attribute
    if force:
        # Get current file attributes
        file_attributes = win32api.GetFileAttributes(path)
        win32api.SetFileAttributes(path, win32con.FILE_ATTRIBUTE_NORMAL)

    try:
        if os.path.isfile(path):
            # A file and a symlinked file are removed the same way
            os.remove(path)
        elif is_link(path):
            # If it's a symlink directory, use the rmdir command
            os.rmdir(path)
        else:
            for name in os.listdir(path):
                item = "{0}\\{1}".format(path, name)
                # If its a normal directory, recurse to remove it's contents
                remove(item, force)

            # rmdir will work now because the directory is empty
            os.rmdir(path)
    except (OSError, IOError) as exc:
        if force:
            # Reset attributes to the original if delete fails.
            win32api.SetFileAttributes(path, file_attributes)
        raise CommandExecutionError("Could not remove '{0}': {1}".format(path, exc))

    return True


def check_perms(
    path,
    ret=None,
    owner=None,
    grant_perms=None,
    deny_perms=None,
    inheritance=True,
    reset=False,
):
    """
    Check owner and permissions for the passed directory. This function checks
    the permissions and sets them, returning the changes made. Used by the file
    state to populate the return dict

    Args:

        path (str):
            The full path to the directory.

        ret (dict):
            A dictionary to append changes to and return. If not passed, will
            create a new dictionary to return.

        owner (str):
            The owner to set for the directory.

        grant_perms (dict):
            A dictionary containing the user/group and the basic permissions to
            check/grant, ie: ``{'user': {'perms': 'basic_permission'}}``.
            Default is ``None``.

        deny_perms (dict):
            A dictionary containing the user/group and permissions to
            check/deny. Default is ``None``.

        inheritance (bool):
            ``True will check if inheritance is enabled and enable it. ``False``
            will check if inheritance is disabled and disable it. Default is
            ``True``.

        reset (bool):
            ``True`` will show what permissions will be removed by resetting the
            DACL. ``False`` will do nothing. Default is ``False``.

    Returns:
        dict: A dictionary of changes that have been made

    CLI Example:

    .. code-block:: bash

        # To see changes to ``C:\\Temp`` if the 'Users' group is given 'read & execute' permissions.
        salt '*' file.check_perms C:\\Temp\\ {} Administrators "{'Users': {'perms': 'read_execute'}}"

        # Locally using salt call
        salt-call file.check_perms C:\\Temp\\ {} Administrators "{'Users': {'perms': 'read_execute', 'applies_to': 'this_folder_only'}}"

        # Specify advanced attributes with a list
        salt '*' file.check_perms C:\\Temp\\ {} Administrators "{'jsnuffy': {'perms': ['read_attributes', 'read_ea'], 'applies_to': 'files_only'}}"
    """
    if not os.path.exists(path):
        raise CommandExecutionError("Path not found: {0}".format(path))

    path = os.path.expanduser(path)

    return __utils__["dacl.check_perms"](
        obj_name=path,
        obj_type="file",
        ret=ret,
        owner=owner,
        grant_perms=grant_perms,
        deny_perms=deny_perms,
        inheritance=inheritance,
        reset=reset,
    )


def is_link(path):
    """
    Check if the path is a symlink

    This is only supported on Windows Vista or later.

    Inline with Unix behavior, this function will raise an error if the path
    is not a symlink, however, the error raised will be a SaltInvocationError,
    not an OSError.

    Args:
        path (str): The path to a file or directory

    Returns:
        bool: True if path is a symlink, otherwise False

    CLI Example:

    .. code-block:: bash

       salt '*' file.is_link /path/to/link
    """
    if sys.getwindowsversion().major < 6:
        raise HubbleInvocationError(
            "Symlinks are only supported on Windows Vista or later."
        )

    try:
        return hubblestack.utils.path.islink(path)
    except Exception as exc:  # pylint: disable=broad-except
        raise CommandExecutionError(exc)


def readlink(path):
    """
    Return the path that a symlink points to

    This is only supported on Windows Vista or later.

    Inline with Unix behavior, this function will raise an error if the path is
    not a symlink, however, the error raised will be a SaltInvocationError, not
    an OSError.

    Args:
        path (str): The path to the symlink

    Returns:
        str: The path that the symlink points to

    CLI Example:

    .. code-block:: bash

        salt '*' file.readlink /path/to/link
    """
    if sys.getwindowsversion().major < 6:
        raise HubbleInvocationError(
            "Symlinks are only supported on Windows Vista or later."
        )

    try:
        return hubblestack.utils.path.readlink(path)
    except OSError as exc:
        if exc.errno == errno.EINVAL:
            raise CommandExecutionError("{0} is not a symbolic link".format(path))
        raise CommandExecutionError(exc.__str__())
    except Exception as exc:  # pylint: disable=broad-except
        raise CommandExecutionError(exc)

