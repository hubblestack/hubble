# -*- encoding: utf-8 -*-
"""
Hubble Nova plugin for running miscellaneous one-off python functions to
run more complex nova audits without allowing arbitrary command execution
from within the yaml profiles.

Sample YAML data, with inline comments:

# Top level key lets the module know it should look at this data
misc:
  # Unique ID for this set of audits
  nodev:
    data:
      # 'osfinger' grain, for multiplatform support
      'Red Hat Enterprise Linux Server-6':
        # tag is required
        tag: CIS-1.1.10
        function: misc_function_name
        args: # optional
          - first_arg
          - second_arg
        kwargs: # optional
          first_kwarg: value
          second_kwarg: value
    labels:
      - critical
      - raiseticket
      # Catch-all, if no other osfinger match was found
      '*':
        tag: generic_tag
        function: misc_function_name
        args: # optional
          - first_arg
          - second_arg
        kwargs: # optional
          first_kwarg: value
          second_kwarg: value
    # Description will be output with the results
    description: '/home should be nodev'
"""

import logging

import fnmatch
import os
import stat
import pathlib
import re
from pystemd.systemd1 import Manager
from hubblestack.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def __virtual__():
    return True


def apply_labels(__data__, labels):
    """
    Filters out the tests whose label doesn't match the labels given when running audit and returns a new data structure with only labelled tests.
    """
    ret = {}
    if labels:
        labelled_test_cases = []
        for test_case in __data__.get("misc", []):
            # each test case is a dictionary with just one key-val pair. key=test name, val=test data, description etc
            if isinstance(test_case, dict) and test_case:
                test_case_body = test_case.get(next(iter(test_case)))
                if test_case_body.get("labels") and set(labels).issubset(set(test_case_body.get("labels", []))):
                    labelled_test_cases.append(test_case)
        ret["misc"] = labelled_test_cases
    else:
        ret = __data__
    return ret


def audit(data_list, tags, labels, debug=False, **kwargs):
    """
    Run the misc audits contained in the data_list
    """
    __data__ = {}
    for profile, data in data_list:
        _merge_yaml(__data__, data, profile)
    __data__ = apply_labels(__data__, labels)
    __tags__ = _get_tags(__data__)

    if debug:
        log.debug("misc audit __data__:")
        log.debug(__data__)
        log.debug("misc audit __tags__:")
        log.debug(__tags__)

    ret = {"Success": [], "Failure": [], "Controlled": []}
    for tag in __tags__:
        if fnmatch.fnmatch(tag, tags):
            for tag_data in __tags__[tag]:
                if "control" in tag_data:
                    ret["Controlled"].append(tag_data)
                    continue
                if "function" not in tag_data:
                    continue

                function = FUNCTION_MAP.get(tag_data["function"])
                if not function:
                    if "Errors" not in ret:
                        ret["Errors"] = []
                    ret["Errors"].append({tag: "No function {0} found".format(tag_data["function"])})
                    continue
                args = tag_data.get("args", [])
                kwargs = tag_data.get("kwargs", {})

                # Call the function
                try:
                    result = function(*args, **kwargs)
                except Exception as exc:
                    if "Errors" not in ret:
                        ret["Errors"] = []
                    ret["Errors"].append(
                        {tag: "An error occurred exeuction function {0}: {1}".format(tag_data["function"], str(exc))}
                    )
                    continue

                if result is True:
                    ret["Success"].append(tag_data)
                elif isinstance(result, str):
                    tag_data["failure_reason"] = result
                    ret["Failure"].append(tag_data)
                else:
                    ret["Failure"].append(tag_data)

    return ret


def _merge_yaml(ret, data, profile=None):
    """
    Merge two yaml dicts together at the misc level
    """
    if "misc" not in ret:
        ret["misc"] = []
    if "misc" in data:
        for key, val in data["misc"].items():
            if profile and isinstance(val, dict):
                val["nova_profile"] = profile
            ret["misc"].append({key: val})
    return ret


def _get_tags(data):
    """
    Retrieve all the tags for this distro from the yaml
    """
    ret = {}
    distro = __grains__.get("osfinger")
    for audit_dict in data.get("misc", []):
        # misc:0
        for audit_id, audit_data in audit_dict.items():
            # misc:0:nodev
            tags_dict = audit_data.get("data", {})
            # misc:0:nodev:data
            tags = None
            for osfinger in tags_dict:
                if osfinger == "*":
                    continue
                osfinger_list = [finger.strip() for finger in osfinger.split(",")]
                for osfinger_glob in osfinger_list:
                    if fnmatch.fnmatch(distro, osfinger_glob):
                        tags = tags_dict.get(osfinger)
                        break
                if tags is not None:
                    break
            # If we didn't find a match, check for a '*'
            if tags is None:
                tags = tags_dict.get("*", {})
            # misc:0:nodev:data:Debian-8
            if "tag" not in tags:
                tags["tag"] = ""
            tag = tags["tag"]
            if tag not in ret:
                ret[tag] = []
            formatted_data = {"tag": tag, "module": "misc"}
            formatted_data.update(audit_data)
            formatted_data.update(tags)
            formatted_data.pop("data")
            ret[tag].append(formatted_data)
    return ret


############################
# Begin function definitions
############################


def _execute_shell_command(cmd, python_shell=False):
    """
    This function will execute passed command in /bin/shell
    """
    return __mods__["cmd.run"](cmd, python_shell=python_shell, shell="/bin/bash", ignore_retcode=True)


def _is_valid_home_directory(directory_path, check_slash_home=False):
    directory_path = None if directory_path is None else directory_path.strip()
    if directory_path is not None and directory_path != "" and os.path.isdir(directory_path):
        if check_slash_home and directory_path == "/":
            return False
        else:
            return True

    return False


def _is_permission_in_limit(max_permission, given_permission):
    """
    Return true only if given_permission is not more lenient that max_permission. In other words, if
    r or w or x is present in given_permission but absent in max_permission, it should return False
    Takes input two integer values from 0 to 7.
    """
    max_permission = int(max_permission)
    given_permission = int(given_permission)
    allowed_r = False
    allowed_w = False
    allowed_x = False
    given_r = False
    given_w = False
    given_x = False

    if max_permission >= 4:
        allowed_r = True
        max_permission = max_permission - 4
    if max_permission >= 2:
        allowed_w = True
        max_permission = max_permission - 2
    if max_permission >= 1:
        allowed_x = True

    if given_permission >= 4:
        given_r = True
        given_permission = given_permission - 4
    if given_permission >= 2:
        given_w = True
        given_permission = given_permission - 2
    if given_permission >= 1:
        given_x = True

    if given_r and (not allowed_r):
        return False
    if given_w and (not allowed_w):
        return False
    if given_x and (not allowed_x):
        return False

    return True


def check_all_ports_firewall_rules():
    """
    Ensure firewall rule for all open ports
    """
    start_open_ports = (
        _execute_shell_command(
            'netstat -ln | grep "Active Internet connections (only servers)" -n | cut -d ":" -f1', python_shell=True
        )
    ).strip()
    end_open_ports = (
        _execute_shell_command(
            'netstat -ln | grep "Active UNIX domain sockets (only servers)" -n  | cut -d ":" -f1', python_shell=True
        )
    ).strip()
    open_ports = (
        _execute_shell_command(
            "netstat -ln | awk 'FNR > "
            + start_open_ports
            + " && FNR < "
            + end_open_ports
            + ' && $6 == "LISTEN" && $4 !~ /127.0.0.1/ {print $4}\' | sed -e "s/.*://"',
            python_shell=True,
        )
    ).strip()
    open_ports = open_ports.split("\n") if open_ports != "" else []
    firewall_ports = (
        _execute_shell_command(
            'iptables -L INPUT -v -n | awk \'FNR > 2 && $11 != "" && $11 ~ /^dpt:/ {print $11}\' | sed -e "s/.*://"',
            python_shell=True,
        )
    ).strip()
    firewall_ports = firewall_ports.split("\n") if firewall_ports != "" else []
    no_firewall_ports = []

    for open_port in open_ports:
        if open_port not in firewall_ports:
            no_firewall_ports.append(open_port)

    return True if len(no_firewall_ports) == 0 else str(no_firewall_ports)


def check_password_fields_not_empty():
    """
    Ensure password fields are not empty
    """
    result = ""
    with open("/etc/shadow", "r") as shadow:
        lines = shadow.readlines()
        for line in lines:
            if line.split(":")[1] is "":
                result += f"{line.split(':')[0]} does not have a password \n"
        return True if result == "" else result


def ungrouped_files_or_dir():
    """
    Ensure no ungrouped files or directories exist
    """
    raise CommandExecutionError("Module disabled due to performance concerns")


def unowned_files_or_dir():
    """
    Ensure no unowned files or directories exist
    """
    raise CommandExecutionError("Module disabled due to performance concerns")


def world_writable_file():
    """
    Ensure no world writable files exist
    """
    raise CommandExecutionError("Module disabled due to performance concerns")


def system_account_non_login(non_login_shell="/sbin/nologin", max_system_uid="500", except_for_users=""):
    """
    Ensure system accounts are non-login
    """

    users_list = ["root", "halt", "sync", "shutdown"]
    for user in except_for_users.split(","):
        if user.strip() != "":
            users_list.append(user.strip())
    result = []
    cmd = __mods__["cmd.run_all"]('egrep -v "^\\+" /etc/passwd')
    for line in cmd["stdout"].split("\n"):
        tokens = line.split(":")
        if (
            tokens[0] not in users_list
            and int(tokens[2]) < int(max_system_uid)
            and tokens[6] not in (non_login_shell, "/bin/false")
        ):
            result.append(line)
    return True if result == [] else str(result)


def sticky_bit_on_world_writable_dirs():
    """
    Ensure sticky bit is set on all world-writable directories
    """
    raise CommandExecutionError("Module disabled due to performance concerns")


def default_group_for_root():
    """
    Ensure default group for the root account is GID 0
    """
    with open("/etc/passwd", "r") as passwd:
        lines = passwd.readlines()
        for line in lines:
            if line[:3] == "root" and line.split(":")[3] == "0":
                return True
        return False


def root_is_only_uid_0_account():
    """
    Ensure root is the only UID 0 account
    """
    uid0_accounts = []
    with open("/etc/passwd", "r") as passwd:
        lines = passwd.readlines()
        for line in lines:
            if line.split(":")[2] == "0":
                uid0_accounts.append(line.split(":")[0])
    if "root" in uid0_accounts:
        return True if len(uid0_accounts) == 1 else False
    else:
        raise Exception("Missing root account")


def test_mount_attrs(mount_name, attribute, check_type="hard"):
    """
    Ensure that a given directory is mounted with appropriate attributes
    If check_type is soft, then in absence of volume, True will be returned
    If check_type is hard, then in absence of volume, False will be returned
    """
    # check that the path exists on system
    command = "test -e " + mount_name
    results = __mods__["cmd.run_all"](command, ignore_retcode=True)
    retcode = results["retcode"]
    if str(retcode) == "1":
        return True if check_type == "soft" else (mount_name + " folder does not exist")

    # if the path exits, proceed with following code
    with open("/proc/mounts", "r") as mounts:
        if not re.search(mount_name, mounts.read(), re.M):
            return True if check_type == "soft" else (mount_name + " is not mounted")
        else:
            for line in mounts.readlines():
                if mount_name in line and attribute not in line:
                    return str(line)
    return True


def check_time_synchronization():
    """
    Ensure that some service is running to synchronize the system clock
    """
    manager = Manager()
    manager.load()
    services = manager.Manager.ListUnitFiles()
    success = any(
        [item for item in services if b"systemd-timesyncd" in item[0] or b"ntpd" in item[0] and b"enabled" in item[1]]
    )
    return success or "neither ntpd nor timesyncd is running"


def restrict_permissions(path, permission):
    """
    Ensure that the file permissions on path are equal or more strict than the  pemissions given in argument
    """
    path_details = __mods__["file.stats"](path)
    given_permission = path_details.get("mode")
    given_permission = given_permission[-3:]
    max_permission = str(permission)
    if (
        _is_permission_in_limit(max_permission[0], given_permission[0])
        and _is_permission_in_limit(max_permission[1], given_permission[1])
        and _is_permission_in_limit(max_permission[2], given_permission[2])
    ):
        return True
    return given_permission


def check_path_integrity():
    """
    Ensure that system PATH variable is not malformed.
    """
    path_value = os.environ.get("PATH")
    output = ""
    for item in path_value.split(":"):
        if item is "":
            output += "Empty Directory in PATH (::)\n"
        if item is ".":
            output += "PATH contains .\n"

    if path_value[-1] is ":":
        output += "Trailing : in PATH\n"

    paths = path_value.split(":")
    for path in paths:
        permissions = os.stat(path)
        if os.path.isdir(path):
            if bool(permissions & stat.S_IWGRP):
                output += f"Group write permissions set on directory {path}\n"
            if bool(permissions & stat.S_IWOTH):
                output += f"Other write permissions set on directory {path}\n"
            if pathlib.Path(path).owner() != "root":
                output += f"{path} is not owned by root\n"
        else:
            output += f"{path} is not a directory\n"

    return True if output.strip() == "" else output


def check_duplicate_uids():
    """
    Return False if any duplicate user id exist in /etc/group file, else return True
    """
    with open("/etc/passwd", "r") as passwd:
        users = [item.split(":")[2] for item in passwd.readlines()]
        duplicate_uids = [item for item in set(users) if users.count(item) > 1]
    if duplicate_uids is None or duplicate_uids == []:
        return True
    return str(duplicate_uids)


def check_duplicate_gids():
    """
    Return False if any duplicate group id exist in /etc/group file, else return True
    """
    with open("/etc/group", "r") as group:
        users = [item.split(":")[2] for item in group.readlines()]
        duplicate_gids = [item for item in set(users) if users.count(item) > 1]
    if duplicate_gids is None or duplicate_gids == []:
        return True
    return str(duplicate_gids)


def check_duplicate_unames():
    """
    Return False if any duplicate user names exist in /etc/group file, else return True
    """
    with open("/etc/passwd", "r") as passwd:
        users = [item.split(":")[0] for item in passwd.readlines()]
        duplicate_unames = [item for item in set(users) if users.count(item) > 1]
    if duplicate_unames is None or duplicate_unames == []:
        return True
    return str(duplicate_unames)


def check_duplicate_gnames():
    """
    Return False if any duplicate group names exist in /etc/group file, else return True
    """
    with open("/etc/group", "r") as group:
        groups = [item.split(":")[0] for item in group.readlines()]
        duplicate_gnames = [item for item in set(groups) if groups.count(item) > 1]
    if duplicate_gnames is None or duplicate_gnames == []:
        return True
    return str(duplicate_gnames)


def check_directory_files_permission(path, permission):
    """
    Check all files permission inside a directory
    """
    blacklisted_characters = "[^a-zA-Z0-9-_/]"
    if "-exec" in path or re.findall(blacklisted_characters, path):
        raise CommandExecutionError("Profile parameter '{0}' not a safe pattern".format(path))
    files_list = _execute_shell_command("find {0} -type f".format(path)).strip()
    files_list = files_list.split("\n") if files_list != "" else []
    bad_permission_files = []
    for file_in_directory in files_list:
        per = restrict_permissions(file_in_directory, permission)
        if per is not True:
            bad_permission_files += [file_in_directory + ": Bad Permission - " + per + ":"]
    return True if bad_permission_files == [] else str(bad_permission_files)


def check_core_dumps():
    """
    Ensure core dumps are restricted
    """
    # TODO fix/replace this broken code - maybe with some LIBC library
    # hard_core_dump_value = _execute_shell_command("grep -R -E \"hard +core\" /etc/security/limits.conf /etc/security/limits.d/ | awk '{print $4}'", python_shell=True).strip()
    # hard_core_dump_value = hard_core_dump_value.split('\n') if hard_core_dump_value != "" else []
    # if '0' in hard_core_dump_value:
    #     return True
    #
    # if hard_core_dump_value is None or hard_core_dump_value == [] or hard_core_dump_value == "":
    #     return "'hard core' not found in any file"
    #
    # return str(hard_core_dump_value)
    return True


def check_service_status(service_name, state):
    """
    Ensure that the given service is in the required state. Return False if it is not in desired state
    Return True otherwise
    state can be enabled or disabled.
    """
    all_services = __mods__["cmd.run"]("systemctl list-unit-files")
    if re.search(service_name, all_services, re.M):
        output = __mods__["cmd.retcode"]("systemctl is-enabled " + service_name, ignore_retcode=True)
        if (state == "disabled" and str(output) == "1") or (state == "enabled" and str(output) == "0"):
            return True
        else:
            return __mods__["cmd.run_stdout"]("systemctl is-enabled " + service_name, ignore_retcode=True)
    else:
        if state == "disabled":
            return True
        else:
            return "Looks like " + service_name + " does not exists. Please check."


def check_ssh_timeout_config():
    """
    Ensure SSH Idle Timeout Interval is configured
    """
    checks = [False, False]
    with open("/etc/ssh/sshd_config", "r") as sshconfig:
        for line in sshconfig.readlines():
            if line.startswith("ClientAliveInterval"):
                try:
                    if int(line.split()[-1]) > 300:
                        return "ClientAliveInterval value should be less than equal to 300"
                    else:
                        checks[0] = True
                except ValueError:
                    raise ValueError("ClientAliveInterval should be an integer")
            if line.startswith("ClientAliveCountMax"):
                try:
                    if int(line.split()[-1]) > 3:
                        return "ClientAliveCountMax value should be less than equal to 3"
                    else:
                        checks[1] = True
                except ValueError:
                    raise ValueError("ClientAliveCountMax should be an integer")
    return all(checks)


def check_unowned_files():
    """
    Ensure no unowned files or directories exist
    """
    raise CommandExecutionError("Module disabled due to performance concerns")


def check_ungrouped_files():
    """
    Ensure no ungrouped files or directories exist
    """
    raise CommandExecutionError("Module disabled due to performance concerns")


def check_all_users_home_directory(max_system_uid):
    """
    Ensure all users' home directories exist
    """
    with open("/etc/passwd", "r") as passwd:
        lines = passwd.readlines()
        users_uids_dirs = [
            " ".join([item.split(":")[0], item.split(":")[2], item.split(":")[5], item.split(":")[6].strip()])
            for item in lines
        ]
    error = []
    for user_data in users_uids_dirs:
        user_uid_dir = user_data.strip().split(" ")
        if len(user_uid_dir) < 4:
            user_uid_dir = user_uid_dir + [""] * (4 - len(user_uid_dir))
        if user_uid_dir[1].isdigit():
            if (
                not _is_valid_home_directory(user_uid_dir[2], True)
                and int(user_uid_dir[1]) >= max_system_uid
                and user_uid_dir[0] != "nfsnobody"
                and "nologin" not in user_uid_dir[3]
                and "false" not in user_uid_dir[3]
            ):
                error += [
                    "Either home directory "
                    + user_uid_dir[2]
                    + " of user "
                    + user_uid_dir[0]
                    + " is invalid or does not exist."
                ]
        else:
            error += ["User " + user_uid_dir[0] + " has invalid uid " + user_uid_dir[1]]
    return True if not error else str(error)


def check_users_home_directory_permissions(max_allowed_permission="750", except_for_users=""):
    """
    Ensure users' home directories permissions are 750 or more restrictive
    """
    users_list = ["root", "halt", "sync", "shutdown"]
    for user in except_for_users.split(","):
        if user.strip() != "":
            users_list.append(user.strip())

    users_dirs = []
    cmd = __mods__["cmd.run_all"]('egrep -v "^\\+" /etc/passwd ')
    for line in cmd["stdout"].split("\n"):
        tokens = line.split(":")
        if tokens[0] not in users_list and "nologin" not in tokens[6] and "false" not in tokens[6]:
            users_dirs.append(tokens[0] + " " + tokens[5])
    error = []
    for user_dir in users_dirs:
        user_dir = user_dir.split(" ")
        if len(user_dir) < 2:
            user_dir = user_dir + [""] * (2 - len(user_dir))
        if _is_valid_home_directory(user_dir[1]):
            result = restrict_permissions(user_dir[1], max_allowed_permission)
            if result is not True:
                error += [
                    "permission on home directory " + user_dir[1] + " of user " + user_dir[0] + " is wrong: " + result
                ]

    return True if error == [] else str(error)


def check_users_own_their_home(max_system_uid):
    """
    Ensure users own their home directories
    """

    max_system_uid = int(max_system_uid)

    with open("/etc/passwd", "r") as passwd:
        lines = passwd.readlines()
        users_uids_dirs = [
            " ".join([item.split(":")[0], item.split(":")[2], item.split(":")[5], item.split(":")[6].strip()])
            for item in lines
        ]
    error = []
    for user_data in users_uids_dirs:
        user_uid_dir = user_data.strip().split(" ")
        if len(user_uid_dir) < 4:
            user_uid_dir = user_uid_dir + [""] * (4 - len(user_uid_dir))
        if user_uid_dir[1].isdigit():
            if not _is_valid_home_directory(user_uid_dir[2]):
                if (
                    int(user_uid_dir[1]) >= max_system_uid
                    and "nologin" not in user_uid_dir[3]
                    and "false" not in user_uid_dir[3]
                ):
                    error += [
                        "Either home directory "
                        + user_uid_dir[2]
                        + " of user "
                        + user_uid_dir[0]
                        + " is invalid or does not exist."
                    ]
            elif (
                int(user_uid_dir[1]) >= max_system_uid
                and user_uid_dir[0] != "nfsnobody"
                and "nologin" not in user_uid_dir[3]
                and "false" not in user_uid_dir[3]
            ):
                owner = __mods__["cmd.run"]('stat -L -c "%U" "' + user_uid_dir[2] + '"')
                if owner != user_uid_dir[0]:
                    error += [
                        "The home directory "
                        + user_uid_dir[2]
                        + " of user "
                        + user_uid_dir[0]
                        + " is owned by "
                        + owner
                    ]
        else:
            error += ["User " + user_uid_dir[0] + " has invalid uid " + user_uid_dir[1]]

    return True if not error else str(error)


def check_users_dot_files():
    """
    Ensure users' dot files are not group or world writable
    """

    to_ignore = lambda x: any([item in x for item in ["root", "halt", "sync", "shutdown", "/sbin/nologin"]])
    users_dirs = []
    with open("/etc/passwd", "r") as passwd:
        lines = passwd.readlines()
        for line in lines:
            if not to_ignore(line):
                users_dirs.append(" ".join([line.split(":")[0], line.split(":")[5]]))

    error = []
    for user_dir in users_dirs:
        user_dir = user_dir.split()
        if len(user_dir) < 2:
            user_dir = user_dir + [""] * (2 - len(user_dir))
        if _is_valid_home_directory(user_dir[1]):
            dot_files = _execute_shell_command("find " + user_dir[1] + ' -name ".*"').strip()
            dot_files = dot_files.split("\n") if dot_files != "" else []
            for dot_file in dot_files:
                if os.path.isfile(dot_file):
                    path_details = __mods__["file.stats"](dot_file)
                    given_permission = path_details.get("mode")
                    file_permission = given_permission[-3:]
                    if file_permission[1] in ["2", "3", "6", "7"]:
                        error += ["Group Write permission set on file " + dot_file + " for user " + user_dir[0]]
                    if file_permission[2] in ["2", "3", "6", "7"]:
                        error += ["Other Write permission set on file " + dot_file + " for user " + user_dir[0]]

    return True if error == [] else str(error)


def check_users_forward_files():
    """
    Ensure no users have .forward files
    """

    error = []
    users_dirs = []
    with open("/etc/passwd", "r") as passwd:
        lines = passwd.readlines()
        for line in lines:
            users_dirs.append(" ".join([line.split(":")[0], line.split(":")[5]]))
    for user_dir in users_dirs:
        user_dir = user_dir.split()
        if len(user_dir) < 2:
            user_dir = user_dir + [""] * (2 - len(user_dir))
        if _is_valid_home_directory(user_dir[1]):
            forward_file = _execute_shell_command("find " + user_dir[1] + ' -maxdepth 1 -name ".forward"').strip()
            if forward_file is not None and os.path.isfile(forward_file):
                error += [
                    "Home directory: " + user_dir[1] + ", for user: " + user_dir[0] + " has " + forward_file + " file"
                ]

    return True if error == [] else str(error)


def check_users_netrc_files():
    """
    Ensure no users have .netrc files
    """

    error = []
    users_dirs = []
    with open("/etc/passwd", "r") as passwd:
        lines = passwd.readlines()
        for line in lines:
            users_dirs.append(" ".join([line.split(":")[0], line.split(":")[5]]))
    for user_dir in users_dirs:
        user_dir = user_dir.split()
        if len(user_dir) < 2:
            user_dir = user_dir + [""] * (2 - len(user_dir))
        if _is_valid_home_directory(user_dir[1]):
            netrc_file = _execute_shell_command("find " + user_dir[1] + ' -maxdepth 1 -name ".netrc"').strip()
            if netrc_file is not None and os.path.isfile(netrc_file):
                error += ["Home directory: " + user_dir[1] + ", for user: " + user_dir[0] + " has .netrc file"]

    return True if error == [] else str(error)


def check_groups_validity():
    """
    Ensure all groups in /etc/passwd exist in /etc/group
    """
    with open("/etc/passwd", "r") as passwd:
        lines = passwd.readlines()
        group_ids_in_passwd = set([line.split(":")[3] for line in lines])
    with open("/etc/group", "r") as group:
        lines = group.readlines()
        group_ids_in_group = set([line.split(":")[2] for line in lines])
    invalid_group_ids = group_ids_in_passwd.difference(group_ids_in_group)
    output_list = [f"Invalid groupid: {item} in /etc/passwd file" for item in invalid_group_ids]

    return True if output_list == [] else str(output_list)


def ensure_reverse_path_filtering():
    """
    Ensure Reverse Path Filtering is enabled
    """
    error_list = []
    command = "sysctl net.ipv4.conf.all.rp_filter 2> /dev/null"
    output = _execute_shell_command(command, python_shell=True)
    if output.strip() == "":
        error_list.append("net.ipv4.conf.all.rp_filter not found")
    search_results = re.findall(r"rp_filter = (\d+)", output)
    result = int(search_results[0])
    if result < 1:
        error_list.append("net.ipv4.conf.all.rp_filter  value set to " + str(result))
    command = "sysctl net.ipv4.conf.default.rp_filter 2> /dev/null"
    output = _execute_shell_command(command, python_shell=True)
    if output.strip() == "":
        error_list.append("net.ipv4.conf.default.rp_filter not found")
    search_results = re.findall(r"rp_filter = (\d+)", output)
    result = int(search_results[0])
    if result < 1:
        error_list.append("net.ipv4.conf.default.rp_filter  value set to " + str(result))
    if len(error_list) > 0:
        return str(error_list)
    else:
        return True


def check_users_rhosts_files():
    """
    Ensure no users have .rhosts files
    """

    to_ignore = lambda x: any([item in x for item in ["root", "halt", "sync", "shutdown", "/sbin/nologin"]])
    users_dirs = []
    with open("/etc/passwd", "r") as passwd:
        lines = passwd.readlines()
        for line in lines:
            if not to_ignore(line):
                users_dirs.append(" ".join([line.split(":")[0], line.split(":")[5]]))
    error = []
    for user_dir in users_dirs:
        user_dir = user_dir.split()
        if len(user_dir) < 2:
            user_dir = user_dir + [""] * (2 - len(user_dir))
        if _is_valid_home_directory(user_dir[1]):
            rhosts_file = _execute_shell_command("find " + user_dir[1] + ' -maxdepth 1 -name ".rhosts"').strip()
            if rhosts_file is not None and os.path.isfile(rhosts_file):
                error += ["Home directory: " + user_dir[1] + ", for user: " + user_dir[0] + " has .rhosts file"]
    return True if error == [] else str(error)


def check_netrc_files_accessibility():
    """
    Ensure users' .netrc Files are not group or world accessible
    """
    to_ignore = lambda x: any([item in x for item in ["root", "halt", "sync", "shutdown", "/sbin/nologin"]])
    users_dirs = []
    with open("/etc/passwd", "r") as passwd:
        lines = passwd.readlines()
        for line in lines:
            if not to_ignore(line):
                users_dirs.append(line.split(":")[5])

    output = ""
    for user_dir in users_dirs:
        net_rc_files = [f for f in pathlib.Path(user_dir).iterdir() if f.is_file() and str(f).endswith(".netrc")]
        for rc_file in net_rc_files:
            permissions = rc_file.stat().st_mode
            if bool(permissions & stat.S_IRGRP):
                output += f"Group Read set on {str(rc_file)}\n"
            if bool(permissions & stat.S_IWGRP):
                output += f"Group Write set on {str(rc_file)}\n"
            if bool(permissions & stat.S_IXGRP):
                output += f"Group Execute set on {str(rc_file)}\n"
            if bool(permissions & stat.S_IROTH):
                output += f"Other Read set on {str(rc_file)}\n"
            if bool(permissions & stat.S_IWOTH):
                output += f"Other Write set on {str(rc_file)}\n"
            if bool(permissions & stat.S_IXOTH):
                output += f"Other Execute set on {str(rc_file)}\n"
    return True if output.strip() == "" else output


def _grep(path, pattern, *args):
    """
    Grep for a string in the specified file

    .. note::
        This function's return value is slated for refinement in future
        versions of Salt

    path
        Path to the file to be searched

        .. note::
            Globbing is supported (i.e. ``/var/log/foo/*.log``, but if globbing
            is being used then the path should be quoted to keep the shell from
            attempting to expand the glob expression.

    pattern
        Pattern to match. For example: ``test``, or ``a[0-5]``

    opts
        Additional command-line flags to pass to the grep command. For example:
        ``-v``, or ``-i -B2``

        .. note::
            The options should come after a double-dash (as shown in the
            examples below) to keep Salt's own argument parser from
            interpreting them.

    CLI Example:

    .. code-block:: bash

        salt '*' file.grep /etc/passwd nobody
        salt '*' file.grep /etc/sysconfig/network-scripts/ifcfg-eth0 ipaddr -- -i
        salt '*' file.grep /etc/sysconfig/network-scripts/ifcfg-eth0 ipaddr -- -i -B2
        salt '*' file.grep "/etc/sysconfig/network-scripts/*" ipaddr -- -i -l
    """
    path = os.path.expanduser(path)

    if args:
        options = " ".join(args)
    else:
        options = ""
    cmd = r"""grep  {options} {pattern} {path}""".format(
        options=options,
        pattern=pattern,
        path=path,
    )

    try:
        ret = __mods__["cmd.run_all"](cmd, python_shell=False, ignore_retcode=True)
    except (IOError, OSError) as exc:
        raise CommandExecutionError(exc.strerror)

    return ret


def check_list_values(file_path, match_pattern, value_pattern, grep_arg, white_list, black_list, value_delimter):
    """
    This function will first get the line matching given match_pattern.
    After this value pattern will be extracted from the above line.
    value pattern will be splitted by value_delimiter to get the list of values.
    match_pattern will be regex patter for grep command.
    value_pattern will be regex for re module of python to get matched values.
    Only one of white_list and blacklist is allowed.
    white_list and black_list should have comma(,) seperated values.

    Example for CIS-2.2.1.2
    ensure_ntp_configured:
      data:
        CentOS Linux-7:
         tag: 2.2.1.2
         function: check_list_values
         args:
           - /etc/ntp.conf
           - '^restrict.*default'
           - '^restrict.*default(.*)$'
           - null
           - kod,nomodify,notrap,nopeer,noquery
           - null
           - ' '
         description: Ensure ntp is configured
    """

    list_delimter = ","

    if black_list is not None and white_list is not None:
        return "Both black_list and white_list values are not allowed."

    grep_args = [] if grep_arg is None else [grep_arg]
    matched_lines = _grep(file_path, match_pattern, *grep_args).get("stdout")
    if not matched_lines:
        return "No match found for the given pattern: " + str(match_pattern)

    matched_lines = matched_lines.split("\n") if matched_lines is not None else []
    error = []
    for matched_line in matched_lines:
        regexp = re.compile(value_pattern)
        matched_values = regexp.search(matched_line).group(1)
        matched_values = matched_values.strip().split(value_delimter) if matched_values is not None else []
        if white_list is not None:
            values_not_in_white_list = list(set(matched_values) - set(white_list.strip().split(list_delimter)))
            if values_not_in_white_list != []:
                error += ["values not in whitelist: " + str(values_not_in_white_list)]
        else:
            values_in_black_list = list(set(matched_values).intersection(set(black_list.strip().split(list_delimter))))
            if values_in_black_list != []:
                error += ["values in blacklist: " + str(values_in_black_list)]

    return True if error == [] else str(error)


def mail_conf_check():
    """
    Ensure mail transfer agent is configured for local-only mode
    """
    valid_addresses = ["localhost", "127.0.0.1", "::1"]
    if os.path.isfile("/etc/postfix/main.cf"):
        with open("/etc/postfix/main.cf") as main_file:
            inet_addresses = [line for line in main_file.readlines() if "inet_interfaces" in line][0]
        mail_addresses = inet_addresses.split("=")[1].replace(" ", "").strip()
        mail_addresses = mail_addresses.split(",") if mail_addresses != "" else []
        mail_addresses = list(map(str.strip, mail_addresses))
        invalid_addresses = list(set(mail_addresses) - set(valid_addresses))
        return str(invalid_addresses) if invalid_addresses != [] else True
    else:
        raise FileNotFoundError("Postfix configuration file missing: /etc/postfix/maain.cf")


def check_if_any_pkg_installed(args):
    """
    :param args: Comma separated list of packages those needs to be verified
    :return: True if any of the input package is installed else False
    """
    for pkg in args.split(","):
        if __mods__["pkg.version"](pkg):
            return True
    return False


def ensure_max_password_expiration(allow_max_days, except_for_users=""):
    """
    Ensure max password expiration days is set to the value less than or equal to that given in args
    """
    grep_args = []
    pass_max_days_output = _grep("/etc/login.defs", "^PASS_MAX_DAYS", *grep_args).get("stdout")
    if not pass_max_days_output:
        return "PASS_MAX_DAYS must be set"
    system_pass_max_days = pass_max_days_output.split()[1]

    if not system_pass_max_days.isnumeric():
        return "PASS_MAX_DAYS must be set properly"
    if int(system_pass_max_days) > allow_max_days:
        return "PASS_MAX_DAYS must be less than or equal to " + str(allow_max_days)

    # fetch all users with passwords
    grep_args.append("-E")
    all_users = _grep("/etc/shadow", r"^[^:]+:[^\!*]", *grep_args).get("stdout")

    except_for_users_list = []
    for user in except_for_users.split(","):
        if user.strip() != "":
            except_for_users_list.append(user.strip())
    result = []
    for line in all_users.split("\n"):
        user = line.split(":")[0]
        # As per CIS doc, 5th field is the password max expiry days
        user_passwd_expiry = line.split(":")[4]
        if (
            not user in except_for_users_list
            and user_passwd_expiry.isnumeric()
            and int(user_passwd_expiry) > allow_max_days
        ):
            result.append(
                "User "
                + user
                + " has max password expiry days "
                + user_passwd_expiry
                + ", which is more than "
                + str(allow_max_days)
            )

    return True if result == [] else str(result)


def check_sshd_parameters(*args, **kwargs):
    """
    Fix spelling while also retaining backwards compatibility
    """
    return check_sshd_paramters(*args, **kwargs)


def check_sshd_paramters(pattern, values=None, comparetype="regex"):
    r"""
    This function will check if any pattern passed is present in ssh service
    User can also check for the values for that pattern
    To check for values in any order, then use comparetype as 'only'
    Example:
    1) To check for INFO for LogLevel
        check_log_level:
            data:
              '*':
               tag: CIS-1.1.1
               function: check_sshd_paramters
               args:
                 - '^LogLevel\s+INFO'
            description: Ensure SSH LogLevel is set to INFO
    2) To check for only approved ciphers in any order
    sshd_approved_cipher:
      data:
        '*':
         tag: CIS-1.1.2
         function: check_sshd_paramters
         args:
           - '^Ciphers'
         kwargs:
           values: aes256-ctr,aes192-ctr,aes128-ctr
           comparetype: only
      description: Ensure only approved ciphers are used
    """
    output = __mods__["cmd.run"]("sshd -T")
    if comparetype == "only":
        if not values:
            return "You need to provide values for comparetype 'only'."
        else:
            for line in output.splitlines():
                if re.match(pattern, line, re.I):
                    expected_values = values.split(",")
                    found_values = line[len(pattern) :].strip().split(",")
                    for found_value in found_values:
                        if found_value in expected_values:
                            continue
                        else:
                            return "Allowed values for pattern: " + pattern + " are " + values
                    return True
            return "Looks like pattern i.e. " + pattern + " not found in sshd -T. Please check."
    elif comparetype == "regex":
        if re.search(pattern, output, re.M | re.I):
            return True
        else:
            return "Looks like pattern i.e. " + pattern + " not found in sshd -T. Please check."
    else:
        return "The comparetype: " + comparetype + " not found. It can be 'regex' or 'only'. Please check."


def test_success():
    """
    Automatically returns success
    """
    return True


def test_failure():
    """
    Automatically returns failure, no reason
    """
    return False


def test_failure_reason(reason):
    """
    Automatically returns failure, with a reason (first arg)
    """
    return reason


FUNCTION_MAP = {
    "check_all_ports_firewall_rules": check_all_ports_firewall_rules,
    "check_password_fields_not_empty": check_password_fields_not_empty,
    "ungrouped_files_or_dir": ungrouped_files_or_dir,
    "unowned_files_or_dir": unowned_files_or_dir,
    "world_writable_file": world_writable_file,
    "system_account_non_login": system_account_non_login,
    "sticky_bit_on_world_writable_dirs": sticky_bit_on_world_writable_dirs,
    "default_group_for_root": default_group_for_root,
    "root_is_only_uid_0_account": root_is_only_uid_0_account,
    "test_success": test_success,
    "test_failure": test_failure,
    "test_failure_reason": test_failure_reason,
    "test_mount_attrs": test_mount_attrs,
    "check_path_integrity": check_path_integrity,
    "restrict_permissions": restrict_permissions,
    "check_time_synchronization": check_time_synchronization,
    "check_core_dumps": check_core_dumps,
    "check_directory_files_permission": check_directory_files_permission,
    "check_duplicate_gnames": check_duplicate_gnames,
    "check_duplicate_unames": check_duplicate_unames,
    "check_duplicate_gids": check_duplicate_gids,
    "check_duplicate_uids": check_duplicate_uids,
    "check_service_status": check_service_status,
    "check_ssh_timeout_config": check_ssh_timeout_config,
    "check_unowned_files": check_unowned_files,
    "check_ungrouped_files": check_ungrouped_files,
    "check_all_users_home_directory": check_all_users_home_directory,
    "check_users_home_directory_permissions": check_users_home_directory_permissions,
    "check_users_own_their_home": check_users_own_their_home,
    "check_users_dot_files": check_users_dot_files,
    "check_users_forward_files": check_users_forward_files,
    "check_users_netrc_files": check_users_netrc_files,
    "check_groups_validity": check_groups_validity,
    "ensure_reverse_path_filtering": ensure_reverse_path_filtering,
    "check_users_rhosts_files": check_users_rhosts_files,
    "check_netrc_files_accessibility": check_netrc_files_accessibility,
    "check_list_values": check_list_values,
    "mail_conf_check": mail_conf_check,
    "check_if_any_pkg_installed": check_if_any_pkg_installed,
    "ensure_max_password_expiration": ensure_max_password_expiration,
    "check_sshd_paramters": check_sshd_paramters,
    "check_sshd_parameters": check_sshd_parameters,
}
