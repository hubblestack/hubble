# -*- coding: utf-8 -*-
"""
Manage information about regular files, directories,
and special files on the minion, set/read user,
group, mode, and data
"""

# Import python libs
import logging
import os
import re
import shutil
import stat
import time
from collections import namedtuple

# Import hubble libs
import hubblestack.utils.files
import hubblestack.utils.hashutils
import hubblestack.utils.path
import hubblestack.utils.platform
import hubblestack.utils.stringutils
import hubblestack.utils.user
import hubblestack.utils.versions

from hubblestack.exceptions import CommandExecutionError, HubbleInvocationError

# pylint: enable=import-error,no-name-in-module,redefined-builtin
try:
    import grp
    import pwd
except ImportError:
    pass

log = logging.getLogger(__name__)

AttrChanges = namedtuple("AttrChanges", "added,removed")


def uid_to_user(uid):
    """
    Convert a uid to a user name

    uid
        uid to convert to a username

    CLI Example:

    .. code-block:: bash

        salt '*' file.uid_to_user 0
    """
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, NameError):
        # If user is not present, fall back to the uid.
        return uid


def user_to_uid(user):
    """
    Convert user name to a uid

    user
        user name to convert to its uid

    CLI Example:

    .. code-block:: bash

        salt '*' file.user_to_uid root
    """
    if user is None:
        user = hubblestack.utils.user.get_user()
    try:
        if isinstance(user, int):
            return user
        return pwd.getpwnam(user).pw_uid
    except KeyError:
        return ""


def gid_to_group(gid):
    """
    Convert the group id to the group name on this system

    gid
        gid to convert to a group name

    CLI Example:

    .. code-block:: bash

        salt '*' file.gid_to_group 0
    """
    try:
        gid = int(gid)
    except ValueError:
        # This is not an integer, maybe it's already the group name?
        gid = group_to_gid(gid)

    if gid == "":
        # Don't even bother to feed it to grp
        return ""

    try:
        return grp.getgrgid(gid).gr_name
    except (KeyError, NameError):
        # If group is not present, fall back to the gid.
        return gid


def group_to_gid(group):
    """
    Convert the group to the gid on this system

    group
        group to convert to its gid

    CLI Example:

    .. code-block:: bash

        salt '*' file.group_to_gid root
    """
    if group is None:
        return ""
    try:
        if isinstance(group, int):
            return group
        return grp.getgrnam(group).gr_gid
    except KeyError:
        return ""


def get_user(path, follow_symlinks=True):
    """
    Return the user that owns a given file

    path
        file or directory of which to get the user

    follow_symlinks
        indicated if symlinks should be followed

    CLI Example:

    .. code-block:: bash

        salt '*' file.get_user /etc/passwd

    .. versionchanged:: 0.16.4
        ``follow_symlinks`` option added
    """
    return stats(os.path.expanduser(path), follow_symlinks=follow_symlinks).get(
        "user", False
    )


def get_mode(path, follow_symlinks=True):
    """
    Return the mode of a file

    path
        file or directory of which to get the mode

    follow_symlinks
        indicated if symlinks should be followed

    CLI Example:

    .. code-block:: bash

        salt '*' file.get_mode /etc/passwd

    .. versionchanged:: 2014.1.0
        ``follow_symlinks`` option added
    """
    return stats(os.path.expanduser(path), follow_symlinks=follow_symlinks).get(
        "mode", ""
    )


def set_mode(path, mode):
    """
    Set the mode of a file

    path
        file or directory of which to set the mode

    mode
        mode to set the path to

    CLI Example:

    .. code-block:: bash

        salt '*' file.set_mode /etc/passwd 0644
    """
    path = os.path.expanduser(path)

    mode = str(mode).lstrip("0Oo")
    if not mode:
        mode = "0"
    if not os.path.exists(path):
        raise CommandExecutionError("{0}: File not found".format(path))
    try:
        os.chmod(path, int(mode, 8))
    except Exception:  # pylint: disable=broad-except
        return "Invalid Mode " + mode
    return get_mode(path)


def lchown(path, user, group):
    """
    Chown a file, pass the file the desired user and group without following
    symlinks.

    path
        path to the file or directory

    user
        user owner

    group
        group owner

    CLI Example:

    .. code-block:: bash

        salt '*' file.chown /etc/passwd root root
    """
    path = os.path.expanduser(path)

    uid = user_to_uid(user)
    gid = group_to_gid(group)
    err = ""
    if uid == "":
        if user:
            err += "User does not exist\n"
        else:
            uid = -1
    if gid == "":
        if group:
            err += "Group does not exist\n"
        else:
            gid = -1

    return os.lchown(path, uid, gid)


def chown(path, user, group):
    """
    Chown a file, pass the file the desired user and group

    path
        path to the file or directory

    user
        user owner

    group
        group owner

    CLI Example:

    .. code-block:: bash

        salt '*' file.chown /etc/passwd root root
    """
    path = os.path.expanduser(path)

    uid = user_to_uid(user)
    gid = group_to_gid(group)
    err = ""
    if uid == "":
        if user:
            err += "User does not exist\n"
        else:
            uid = -1
    if gid == "":
        if group:
            err += "Group does not exist\n"
        else:
            gid = -1
    if not os.path.exists(path):
        try:
            # Broken symlinks will return false, but still need to be chowned
            return os.lchown(path, uid, gid)
        except OSError:
            pass
        err += "File not found"
    if err:
        return err
    return os.chown(path, uid, gid)


def get_group(path, follow_symlinks=True):
    """
    Return the group that owns a given file

    path
        file or directory of which to get the group

    follow_symlinks
        indicated if symlinks should be followed

    CLI Example:

    .. code-block:: bash

        salt '*' file.get_group /etc/passwd

    .. versionchanged:: 0.16.4
        ``follow_symlinks`` option added
    """
    return stats(os.path.expanduser(path), follow_symlinks=follow_symlinks).get(
        "group", False
    )


def get_selinux_context(path):
    """
    Get an SELinux context from a given path

    CLI Example:

    .. code-block:: bash

        salt '*' file.get_selinux_context /etc/hosts
    """
    cmd_ret = __mods__["cmd.run_all"](["stat", "-c", "%C", path], python_shell=False)

    if cmd_ret["retcode"] == 0:
        ret = cmd_ret["stdout"]
    else:
        ret = "No selinux context information is available for {0}".format(path)

    return ret


def set_selinux_context(
        path,
        user=None,
        role=None,
        type=None,  # pylint: disable=W0622
        range=None,  # pylint: disable=W0622
        persist=False,
):
    """
    .. versionchanged:: 3001

        Added persist option

    Set a specific SELinux label on a given path

    CLI Example:

    .. code-block:: bash

        salt '*' file.set_selinux_context path <user> <role> <type> <range>
        salt '*' file.set_selinux_context /etc/yum.repos.d/epel.repo system_u object_r system_conf_t s0
    """
    if not any((user, role, type, range)):
        return False

    if persist:
        fcontext_result = __mods__["selinux.fcontext_add_policy"](
            path, sel_type=type, sel_user=user, sel_level=range
        )
        if fcontext_result.get("retcode", None) != 0:
            # Problem setting fcontext policy
            raise CommandExecutionError(
                "Problem setting fcontext: {0}".format(fcontext_result)
            )

    cmd = ["chcon"]
    if user:
        cmd.extend(["-u", user])
    if role:
        cmd.extend(["-r", role])
    if type:
        cmd.extend(["-t", type])
    if range:
        cmd.extend(["-l", range])
    cmd.append(path)

    ret = not __mods__["cmd.retcode"](cmd, python_shell=False)
    if ret:
        return get_selinux_context(path)
    else:
        return ret


def _cmp_attrs(path, attrs):
    """
    .. versionadded:: 2018.3.0

    Compare attributes of a given file to given attributes.
    Returns a pair (list) where first item are attributes to
    add and second item are to be removed.

    Please take into account when using this function that some minions will
    not have lsattr installed.

    path
        path to file to compare attributes with.

    attrs
        string of attributes to compare against a given file
    """
    # lsattr for AIX is not the same thing as lsattr for linux.
    if hubblestack.utils.platform.is_aix():
        return None

    try:
        lattrs = lsattr(path).get(path, "")
    except AttributeError:
        # lsattr not installed
        return None

    new = set(attrs)
    old = set(lattrs)

    return AttrChanges(
        added="".join(new - old) or None, removed="".join(old - new) or None,
    )


def _chattr_version():
    """
    Return the version of chattr installed
    """
    # There's no really *good* way to get the version of chattr installed.
    # It's part of the e2fsprogs package - we could try to parse the version
    # from the package manager, but there's no guarantee that it was
    # installed that way.
    #
    # The most reliable approach is to just check tune2fs, since that should
    # be installed with chattr, at least if it was installed in a conventional
    # manner.
    #
    # See https://unix.stackexchange.com/a/520399/5788 for discussion.
    tune2fs = hubblestack.utils.path.which("tune2fs")
    if not tune2fs or hubblestack.utils.platform.is_aix():
        return None
    cmd = [tune2fs]
    result = __mods__["cmd.run"](cmd, ignore_retcode=True, python_shell=False)
    match = re.search(
        r"tune2fs (?P<version>[0-9\.]+)", hubblestack.utils.stringutils.to_str(result),
    )
    if match is None:
        version = None
    else:
        version = match.group("version")

    return version


def _chattr_has_extended_attrs():
    """
    Return ``True`` if chattr supports extended attributes, that is,
    the version is >1.41.22. Otherwise, ``False``
    """
    ver = _chattr_version()
    if ver is None:
        return False

    needed_version = hubblestack.utils.versions.LooseVersion("1.41.12")
    chattr_version = hubblestack.utils.versions.LooseVersion(ver)
    return chattr_version > needed_version


def lsattr(path):
    """
    .. versionadded:: 2018.3.0
    .. versionchanged:: 2018.3.1
        If ``lsattr`` is not installed on the system, ``None`` is returned.
    .. versionchanged:: 2018.3.4
        If on ``AIX``, ``None`` is returned even if in filesystem as lsattr on ``AIX``
        is not the same thing as the linux version.

    Obtain the modifiable attributes of the given file. If path
    is to a directory, an empty list is returned.

    path
        path to file to obtain attributes of. File/directory must exist.

    CLI Example:

    .. code-block:: bash

        salt '*' file.lsattr foo1.txt
    """
    if not hubblestack.utils.path.which("lsattr") or hubblestack.utils.platform.is_aix():
        return None

    if not os.path.exists(path):
        raise HubbleInvocationError("File or directory does not exist: " + path)

    cmd = ["lsattr", path]
    result = __mods__["cmd.run"](cmd, ignore_retcode=True, python_shell=False)

    results = {}
    for line in result.splitlines():
        if not line.startswith("lsattr: "):
            attrs, file = line.split(None, 1)
            if _chattr_has_extended_attrs():
                pattern = r"[aAcCdDeijPsStTu]"
            else:
                pattern = r"[acdijstuADST]"
            results[file] = re.findall(pattern, attrs)

    return results


def chattr(*files, **kwargs):
    """
    .. versionadded:: 2018.3.0

    Change the attributes of files. This function accepts one or more files and
    the following options:

    operator
        Can be wither ``add`` or ``remove``. Determines whether attributes
        should be added or removed from files

    attributes
        One or more of the following characters: ``aAcCdDeijPsStTu``,
        representing attributes to add to/remove from files

    version
        a version number to assign to the file(s)

    flags
        One or more of the following characters: ``RVf``, representing
        flags to assign to chattr (recurse, verbose, suppress most errors)

    CLI Example:

    .. code-block:: bash

        salt '*' file.chattr foo1.txt foo2.txt operator=add attributes=ai
        salt '*' file.chattr foo3.txt operator=remove attributes=i version=2
    """
    operator = kwargs.pop("operator", None)
    attributes = kwargs.pop("attributes", None)
    flags = kwargs.pop("flags", None)
    version = kwargs.pop("version", None)

    if (operator is None) or (operator not in ("add", "remove")):
        raise HubbleInvocationError(
            "Need an operator: 'add' or 'remove' to modify attributes."
        )
    if attributes is None:
        raise HubbleInvocationError("Need attributes: [aAcCdDeijPsStTu]")

    cmd = ["chattr"]

    if operator == "add":
        attrs = "+{0}".format(attributes)
    elif operator == "remove":
        attrs = "-{0}".format(attributes)

    cmd.append(attrs)

    if flags is not None:
        cmd.append("-{0}".format(flags))

    if version is not None:
        cmd.extend(["-v", version])

    cmd.extend(files)

    result = __mods__["cmd.run"](cmd, python_shell=False)

    if bool(result):
        return False

    return True


def check_perms(
        name,
        ret,
        user,
        group,
        mode,
        attrs=None,
        follow_symlinks=False,
        seuser=None,
        serole=None,
        setype=None,
        serange=None,
):
    """
    .. versionchanged:: 3001

        Added selinux options

    Check the permissions on files, modify attributes and chown if needed. File
    attributes are only verified if lsattr(1) is installed.

    CLI Example:

    .. code-block:: bash

        salt '*' file.check_perms /etc/sudoers '{}' root root 400 ai

    .. versionchanged:: 2014.1.3
        ``follow_symlinks`` option added
    """
    name = os.path.expanduser(name)

    if not ret:
        ret = {"name": name, "changes": {}, "comment": [], "result": True}
        orig_comment = ""
    else:
        orig_comment = ret["comment"]
        ret["comment"] = []

    # Check permissions
    perms = {}
    cur = stats(name, follow_symlinks=follow_symlinks)
    perms["luser"] = cur["user"]
    perms["lgroup"] = cur["group"]
    perms["lmode"] = hubblestack.utils.files.normalize_mode(cur["mode"])

    is_dir = os.path.isdir(name)
    is_link = os.path.islink(name)

    # user/group changes if needed, then check if it worked
    if user:
        if isinstance(user, int):
            user = uid_to_user(user)
        if (
                hubblestack.utils.platform.is_windows()
                and user_to_uid(user) != user_to_uid(perms["luser"])
        ) or (not hubblestack.utils.platform.is_windows() and user != perms["luser"]):
            perms["cuser"] = user

    if group:
        if isinstance(group, int):
            group = gid_to_group(group)
        if (
                hubblestack.utils.platform.is_windows()
                and group_to_gid(group) != group_to_gid(perms["lgroup"])
        ) or (not hubblestack.utils.platform.is_windows() and group != perms["lgroup"]):
            perms["cgroup"] = group

    if "cuser" in perms or "cgroup" in perms:
        if not __opts__["test"]:
            if os.path.islink(name) and not follow_symlinks:
                chown_func = lchown
            else:
                chown_func = chown
            if user is None:
                user = perms["luser"]
            if group is None:
                group = perms["lgroup"]
            try:
                chown_func(name, user, group)
                # Python os.chown() does reset the suid and sgid,
                # that's why setting the right mode again is needed here.
                set_mode(name, mode)
            except OSError:
                ret["result"] = False

    if user:
        if isinstance(user, int):
            user = uid_to_user(user)
        if (
                hubblestack.utils.platform.is_windows()
                and user_to_uid(user)
                != user_to_uid(get_user(name, follow_symlinks=follow_symlinks))
                and user != ""
        ) or (
                not hubblestack.utils.platform.is_windows()
                and user != get_user(name, follow_symlinks=follow_symlinks)
                and user != ""
        ):
            if __opts__["test"] is True:
                ret["changes"]["user"] = user
            else:
                ret["result"] = False
                ret["comment"].append("Failed to change user to {0}".format(user))
        elif "cuser" in perms and user != "":
            ret["changes"]["user"] = user

    if group:
        if isinstance(group, int):
            group = gid_to_group(group)
        if (
                hubblestack.utils.platform.is_windows()
                and group_to_gid(group)
                != group_to_gid(get_group(name, follow_symlinks=follow_symlinks))
                and user != ""
        ) or (
                not hubblestack.utils.platform.is_windows()
                and group != get_group(name, follow_symlinks=follow_symlinks)
                and user != ""
        ):
            if __opts__["test"] is True:
                ret["changes"]["group"] = group
            else:
                ret["result"] = False
                ret["comment"].append("Failed to change group to {0}".format(group))
        elif "cgroup" in perms and user != "":
            ret["changes"]["group"] = group

    # Mode changes if needed
    if mode is not None:
        # File is a symlink, ignore the mode setting
        # if follow_symlinks is False
        if os.path.islink(name) and not follow_symlinks:
            pass
        else:
            mode = hubblestack.utils.files.normalize_mode(mode)
            if mode != perms["lmode"]:
                if __opts__["test"] is True:
                    ret["changes"]["mode"] = mode
                else:
                    set_mode(name, mode)
                    if mode != hubblestack.utils.files.normalize_mode(get_mode(name)):
                        ret["result"] = False
                        ret["comment"].append(
                            "Failed to change mode to {0}".format(mode)
                        )
                    else:
                        ret["changes"]["mode"] = mode

    # Modify attributes of file if needed
    if attrs is not None and not is_dir:
        # File is a symlink, ignore the mode setting
        # if follow_symlinks is False
        if os.path.islink(name) and not follow_symlinks:
            pass
        else:
            diff_attrs = _cmp_attrs(name, attrs)
            if diff_attrs and any(attr for attr in diff_attrs):
                changes = {
                    "old": "".join(lsattr(name)[name]),
                    "new": None,
                }
                if __opts__["test"] is True:
                    changes["new"] = attrs
                else:
                    if diff_attrs.added:
                        chattr(
                            name, operator="add", attributes=diff_attrs.added,
                        )
                    if diff_attrs.removed:
                        chattr(
                            name, operator="remove", attributes=diff_attrs.removed,
                        )
                    cmp_attrs = _cmp_attrs(name, attrs)
                    if any(attr for attr in cmp_attrs):
                        ret["result"] = False
                        ret["comment"].append(
                            "Failed to change attributes to {0}".format(attrs)
                        )
                        changes["new"] = "".join(lsattr(name)[name])
                    else:
                        changes["new"] = attrs
                if changes["old"] != changes["new"]:
                    ret["changes"]["attrs"] = changes

    # Set selinux attributes if needed
    if hubblestack.utils.platform.is_linux() and (seuser or serole or setype or serange):
        selinux_error = False
        try:
            (
                current_seuser,
                current_serole,
                current_setype,
                current_serange,
            ) = get_selinux_context(name).split(":")
            log.debug(
                "Current selinux context user:{0} role:{1} type:{2} range:{3}".format(
                    current_seuser, current_serole, current_setype, current_serange
                )
            )
        except ValueError:
            log.error("Unable to get current selinux attributes")
            ret["result"] = False
            ret["comment"].append("Failed to get selinux attributes")
            selinux_error = True

        if not selinux_error:
            requested_seuser = None
            requested_serole = None
            requested_setype = None
            requested_serange = None
            # Only set new selinux variables if updates are needed
            if seuser and seuser != current_seuser:
                requested_seuser = seuser
            if serole and serole != current_serole:
                requested_serole = serole
            if setype and setype != current_setype:
                requested_setype = setype
            if serange and serange != current_serange:
                requested_serange = serange

            if (
                    requested_seuser
                    or requested_serole
                    or requested_setype
                    or requested_serange
            ):
                # selinux updates needed, prep changes output
                selinux_change_new = ""
                selinux_change_orig = ""
                if requested_seuser:
                    selinux_change_new += "User: {0} ".format(requested_seuser)
                    selinux_change_orig += "User: {0} ".format(current_seuser)
                if requested_serole:
                    selinux_change_new += "Role: {0} ".format(requested_serole)
                    selinux_change_orig += "Role: {0} ".format(current_serole)
                if requested_setype:
                    selinux_change_new += "Type: {0} ".format(requested_setype)
                    selinux_change_orig += "Type: {0} ".format(current_setype)
                if requested_serange:
                    selinux_change_new += "Range: {0} ".format(requested_serange)
                    selinux_change_orig += "Range: {0} ".format(current_serange)

                if __opts__["test"]:
                    ret["comment"] = "File {0} selinux context to be updated".format(
                        name
                    )
                    ret["result"] = None
                    ret["changes"]["selinux"] = {
                        "Old": selinux_change_orig.strip(),
                        "New": selinux_change_new.strip(),
                    }
                else:
                    try:
                        # set_selinux_context requires type to be set on any other change
                        if (
                                requested_seuser or requested_serole or requested_serange
                        ) and not requested_setype:
                            requested_setype = current_setype
                        result = set_selinux_context(
                            name,
                            user=requested_seuser,
                            role=requested_serole,
                            type=requested_setype,
                            range=requested_serange,
                            persist=True,
                        )
                        log.debug("selinux set result: {0}".format(result))
                        (
                            current_seuser,
                            current_serole,
                            current_setype,
                            current_serange,
                        ) = result.split(":")
                    except ValueError:
                        log.error("Unable to set current selinux attributes")
                        ret["result"] = False
                        ret["comment"].append("Failed to set selinux attributes")
                        selinux_error = True

                    if not selinux_error:
                        ret["comment"].append(
                            "The file {0} is set to be changed".format(name)
                        )

                        if requested_seuser:
                            if current_seuser != requested_seuser:
                                ret["comment"].append("Unable to update seuser context")
                                ret["result"] = False
                        if requested_serole:
                            if current_serole != requested_serole:
                                ret["comment"].append("Unable to update serole context")
                                ret["result"] = False
                        if requested_setype:
                            if current_setype != requested_setype:
                                ret["comment"].append("Unable to update setype context")
                                ret["result"] = False
                        if requested_serange:
                            if current_serange != requested_serange:
                                ret["comment"].append(
                                    "Unable to update serange context"
                                )
                                ret["result"] = False
                        ret["changes"]["selinux"] = {
                            "Old": selinux_change_orig.strip(),
                            "New": selinux_change_new.strip(),
                        }

    # Only combine the comment list into a string
    # after all comments are added above
    if isinstance(orig_comment, str):
        if orig_comment:
            ret["comment"].insert(0, orig_comment)
        ret["comment"] = "; ".join(ret["comment"])

    # Set result to None at the very end of the function,
    # after all changes have been recorded above
    if __opts__["test"] is True and ret["changes"]:
        ret["result"] = None

    return ret, perms


def get_hash(path, form="sha256", chunk_size=65536):
    """
    Get the hash sum of a file

    This is better than ``get_sum`` for the following reasons:
        - It does not read the entire file into memory.
        - It does not return a string on error. The returned value of
            ``get_sum`` cannot really be trusted since it is vulnerable to
            collisions: ``get_sum(..., 'xyz') == 'Hash xyz not supported'``

    path
        path to the file or directory

    form
        desired sum format

    chunk_size
        amount to sum at once

    CLI Example:

    .. code-block:: bash

        salt '*' file.get_hash /etc/shadow
    """
    return hubblestack.utils.hashutils.get_hash(os.path.expanduser(path), form, chunk_size)


def stats(path, hash_type=None, follow_symlinks=True):
    """
    Return a dict containing the stats for a given file

    CLI Example:

    .. code-block:: bash

        salt '*' file.stats /etc/passwd
    """
    path = os.path.expanduser(path)

    ret = {}
    if not os.path.exists(path):
        try:
            # Broken symlinks will return False for os.path.exists(), but still
            # have a uid and gid
            pstat = os.lstat(path)
        except OSError:
            # Not a broken symlink, just a nonexistent path
            # NOTE: The file.directory state checks the content of the error
            # message in this exception. Any changes made to the message for this
            # exception will reflect the file.directory state as well, and will
            # likely require changes there.
            raise CommandExecutionError("Path not found: {0}".format(path))
    else:
        if follow_symlinks:
            pstat = os.stat(path)
        else:
            pstat = os.lstat(path)
    ret["inode"] = pstat.st_ino
    ret["uid"] = pstat.st_uid
    ret["gid"] = pstat.st_gid
    ret["group"] = gid_to_group(pstat.st_gid)
    ret["user"] = uid_to_user(pstat.st_uid)
    ret["atime"] = pstat.st_atime
    ret["mtime"] = pstat.st_mtime
    ret["ctime"] = pstat.st_ctime
    ret["size"] = pstat.st_size
    ret["mode"] = hubblestack.utils.files.normalize_mode(oct(stat.S_IMODE(pstat.st_mode)))
    if hash_type:
        ret["sum"] = get_hash(path, hash_type)
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


def touch(name, atime=None, mtime=None):
    """
    .. versionadded:: 0.9.5

    Just like the ``touch`` command, create a file if it doesn't exist or
    simply update the atime and mtime if it already does.

    atime:
        Access time in Unix epoch time
    mtime:
        Last modification in Unix epoch time

    CLI Example:

    .. code-block:: bash

        salt '*' file.touch /var/log/emptyfile
    """
    name = os.path.expanduser(name)

    if atime and atime.isdigit():
        atime = int(atime)
    if mtime and mtime.isdigit():
        mtime = int(mtime)
    try:
        if not os.path.exists(name):
            with hubblestack.utils.files.fopen(name, "a"):
                pass

        if not atime and not mtime:
            times = None
        elif not mtime and atime:
            times = (atime, time.time())
        elif not atime and mtime:
            times = (time.time(), mtime)
        else:
            times = (atime, mtime)
        os.utime(name, times)

    except TypeError:
        raise HubbleInvocationError("atime and mtime must be integers")
    except (IOError, OSError) as exc:
        raise CommandExecutionError(exc.strerror)

    return os.path.exists(name)


def remove(path):
    """
    Remove the named file. If a directory is supplied, it will be recursively
    deleted.

    CLI Example:

    .. code-block:: bash

        salt '*' file.remove /tmp/foo

    .. versionchanged:: Neon
        The method now works on all types of file system entries, not just
        files, directories and symlinks.
    """
    path = os.path.expanduser(path)

    if not os.path.isabs(path):
        raise HubbleInvocationError("File path must be absolute: {0}".format(path))

    try:
        if os.path.islink(path) or (os.path.exists(path) and not os.path.isdir(path)):
            os.remove(path)
            return True
        elif os.path.isdir(path):
            shutil.rmtree(path)
            return True
    except (OSError, IOError) as exc:
        raise CommandExecutionError("Could not remove '{0}': {1}".format(path, exc))
    return False


def get_hash(path, form="sha256", chunk_size=65536):
    """
    Get the hash sum of a file
    This is better than ``get_sum`` for the following reasons:
        - It does not read the entire file into memory.
        - It does not return a string on error. The returned value of
            ``get_sum`` cannot really be trusted since it is vulnerable to
            collisions: ``get_sum(..., 'xyz') == 'Hash xyz not supported'``
    path
        path to the file or directory
    form
        desired sum format
    chunk_size
        amount to sum at once
    CLI Example:
    .. code-block:: bash
        salt '*' file.get_hash /etc/shadow
    """
    return hubblestack.utils.hashutils.get_hash(os.path.expanduser(path), form, chunk_size)


def get_sum(path, form="sha256"):
    """
    Return the checksum for the given file. The following checksum algorithms
    are supported:
    * md5
    * sha1
    * sha224
    * sha256 **(default)**
    * sha384
    * sha512
    path
        path to the file or directory
    form
        desired sum format
    CLI Example:
    .. code-block:: bash
        salt '*' file.get_sum /etc/passwd sha512
    """
    path = os.path.expanduser(path)

    if not os.path.isfile(path):
        return "File not found"
    return hubblestack.utils.hashutils.get_hash(path, form, 4096)
