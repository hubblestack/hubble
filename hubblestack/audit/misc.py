# -*- encoding: utf-8 -*-
"""
Hubble Audit plugin for running miscellaneous one-off python functions to
run more complex Audit audits without allowing arbitrary command execution
from within the yaml profiles.

Note: This module is only available through Audit
This module is having different functions for its dedicated purpose.

Usable in Modules
-----------------
- Audit (Only)

Common Schema
-------------
- check_unique_id
    Its a unique string within a yaml file.
    It is present on top of a yaml block

- description
    Description of the check

- tag
    (Applicable only for Audit)
    Check tag value

- sub_check (Optional, default: false)
    (Applicable only for Audit)
    If true, its individual result will not be counted in compliance
    It might be referred in some boolean expression

- failure_reason (Optional)
    (Applicable only for Audit)
    By default, module will generate failure reason string at runtime
    If this is passed, this will override module's actual failure reason

- invert_result (Optional, default: false)
    (Applicable only for Audit)
    This is used to flip the boolean output from a check

- implementations
    (Applicable only for Audit)
    Its an array of implementations, usually for multiple operating systems.
    You can specify multiple implementations here for respective operating system.
    Either one or none will be executed.

- grains (under filter)
    (Applicable only for Audit)
    Any grains with and/or/not supported. This is used to filter whether
    this check can run on the current OS or not.
    To run this check on all OS, put a '*'

    Example:
    G@docker_details:installed:True and G@docker_details:running:True and not G@osfinger:*Flatcar* and not G@osfinger:*CoreOS*

- hubble_version (Optional)
    (Applicable only for Audit)
    It acts as a second level filter where you can specify for which Hubble version,
    this check is compatible with. You can specify a boolean expression as well

    Example:
    '>3.0 AND <5.0'

- module
    The name of Hubble module.

- return_no_exec (Optional, Default: false)
    (Applicable only for Audit)
    It takes a boolean (true/false) value.
    If its true, the implementation will not be executed. And true is returned

    This can be useful in cases where you don't have any implementation for some OS,
    and you want a result from the block. Else, your meta-check(bexpr) will be failed.

- items
    (Applicable only for Audit)
    An array of multiple module implementations. At least one block is necessary.
    Each item in array will result into a boolean value.
    If multiple module implementations exists, final result will be evaluated as
    boolean AND (default, see parameter: check_eval_logic)

- check_eval_logic (Optional, default: and)
    (Applicable only for Audit)
    If there are multiple module implementations in "items" (above parameter), this parameter
    helps in evaluating their result. Default value is "and"
    It accepts only values: and/or

- args
    Arguments specific to a module.

- comparator
    For the purpose of comparing output of module with expected values.
    Parameters depends upon the comparator used.
    For detailed documentation on comparators,
    read comparator's implementations at (/hubblestack/extmods/comparators/)

Module Arguments
----------------
- function
    Function name to execute
- Arguments for functions
    There are different arguments for the function used
    See below documentation for each function

Functions supported:
--------------------
- check_all_ports_firewall_rules
    Ensure firewall rule for all open ports
- check_password_fields_not_empty
    Ensure password fields are not empty
- system_account_non_login
    Ensure system accounts are non-login
    Params:
        non_login_shell - Default value '/sbin/nologin'
        max_system_uid - Default value '500'
        except_for_users - Default value ''
- default_group_for_root
    Ensure default group for the root account is GID 0
- root_is_only_uid_0_account
    Ensure root is the only UID 0 account
- test_success
    Automatically returns success
- test_failure
    Automatically returns failure, no reason
- test_failure_reason
    Automatically returns failure, with a reason
- check_path_integrity
    Ensure that system PATH variable is not malformed.
- check_time_synchronization
    Ensure that some service is running to synchronize the system clock
- check_core_dumps
    Ensure core dumps are restricted
- check_directory_files_permission
    Check all files permission inside a directory
    Params:
        path (Mandatory)
        permission (Mandatory)
- check_duplicate_gnames
    Return False if any duplicate group names exist in /etc/group file, else return True
- check_duplicate_unames
    Return False if any duplicate user names exist in /etc/group file, else return True
- check_duplicate_gids
    Return False if any duplicate group id exist in /etc/group file, else return True
- check_duplicate_uids
    Return False if any duplicate user id exist in /etc/group file, else return True
- check_service_status
    Ensure that the given service is in the required state. Return False if it is not in desired state
    Params:
        service_name (Mandatory)
        state (Mandatory)
- check_ssh_timeout_config
    Ensure SSH Idle Timeout Interval is configured
- check_all_users_home_directory
    Ensure all users' home directories exist
- check_users_home_directory_permissions
    Ensure users' home directories permissions are 750 or more restrictive
    Params:
        max_allowed_permission (Default 750)
        except_for_users (Default '')
- check_users_own_their_home
    Ensure users own their home directories
    Params:
        max_system_uid (Mandatory)
- check_users_dot_files
    Ensure users' dot files are not group or world writable
- check_users_forward_files
    Ensure no users have .forward files
- check_users_netrc_files
    Ensure no users have .netrc files
- check_groups_validity
    Ensure all groups in /etc/passwd exist in /etc/group
- ensure_reverse_path_filtering
    Ensure Reverse Path Filtering is enabled
- check_users_rhosts_files
    Ensure no users have .rhosts files
- check_netrc_files_accessibility
    Ensure users' .netrc Files are not group or world accessible
- check_list_values
    This function will first get the line matching given match_pattern.
    After this value pattern will be extracted from the above line.
    Params:
        file_path (Mandatory)
        match_pattern (Mandatory)
        value_pattern (Mandatory)
        grep_arg (Mandatory)
        white_list (Mandatory)
        black_list (Mandatory)
        value_delimter (Mandatory)
- mail_conf_check
    Ensure mail transfer agent is configured for local-only mode
- ensure_max_password_expiration
    Ensure max password expiration days is set to the value less than or equal to that given in args
    Params:
        allow_max_days (Mandatory)
        except_for_users (Default '')
- check_sshd_parameters
    This function will check if any pattern passed is present in ssh service
    User can also check for the values for that pattern
    Params:
        pattern (Mandatory)
        values (Mandatory)
        comparetype (Default 'regex')

Module Output
-------------
It always return None for success and error message for failure

Output: (True, None)
Note: Module returns a tuple
    First value being the status of module
    Second value is the actual output from module

Compatible Comparators
----------------------
- boolean

For detailed documentation on comparators,
read comparator's implementations at (/hubblestack/extmods/comparators/)


Audit Example:
---------------
Sample Audit Profile Example for one method:

ensure_ntp_configured:
  description: 'Ensure NTP configured'
  tag: 'ADOBE-XYZ'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      module: misc
      items:
        - args:
            function: check_list_values
            file_path: /etc/ntp.conf
            match_pattern: '^restrict.*default'
            value_pattern:: '^restrict.*default(.*)$'
            grep_arg: ''
            white_list: kod,nomodify,notrap,nopeer,noquery
            black_list: ''
            value_delimter: ' '
          comparator:
            type: "boolean"
            match: true

"""
import os
import logging

import re

from hubblestack.exceptions import CommandExecutionError
from collections import Counter

import hubblestack.module_runner.comparator
from hubblestack.module_runner.runner import Caller
import hubblestack.module_runner.runner_utils as runner_utils
from hubblestack.exceptions import HubbleCheckValidationError
import hubblestack.audit.grep as grep_module

log = logging.getLogger(__name__)


def validate_params(block_id, block_dict, extra_args=None):
    """
    Validate all mandatory params required for this module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "/some/path/file.txt", 'status': True},
                  'caller': 'Audit'}

    Raises:
        HubbleCheckValidationError: For any validation error
    """
    log.debug('Module: misc Start validating params for check-id: {0}'.format(block_id))

    error = {}

    # This module is callable from Audit only
    if extra_args.get('caller') == Caller.FDG:
        error['misc'] = 'Module: misc called from FDG !!!!'

    # fetch required param
    function_name = runner_utils.get_param_for_module(block_id, block_dict, 'function')

    if not function_name:
        error['function'] = 'function not provided for block_id: {0}'.format(block_id)
    elif function_name not in FUNCTION_MAP:
        error['function'] = 'Unsupported function name: {0} for block_id: {1}'.format(function_name, block_id)
    else:
        if function_name == 'check_directory_files_permission':
            _validation_helper(block_id, block_dict, ['path', 'permission'], error)
        elif function_name == 'check_service_status':
            _validation_helper(block_id, block_dict, ['service_name', 'state'], error)
        elif function_name == 'check_all_users_home_directory':
            _validation_helper(block_id, block_dict, ['max_system_uid'], error)
        elif function_name == 'check_users_own_their_home':
            _validation_helper(block_id, block_dict, ['max_system_uid'], error)
        elif function_name == 'check_list_values':
            _validation_helper(block_id, 
                block_dict, 
                ['file_path', 'match_pattern', 'value_pattern', 'value_delimter'],
                error)
        elif function_name == 'ensure_max_password_expiration':
            _validation_helper(block_id, block_dict, ['allow_max_days', 'except_for_users'], error)
        elif function_name == 'check_sshd_parameters':
            _validation_helper(block_id, block_dict, ['pattern', 'values', 'comparetype'], error)

    if error:
        raise HubbleCheckValidationError(error)

    log.debug('Validation success for check-id: {0}'.format(block_id))

def _validation_helper(block_id, block_dict, expected_args_list, error_dict):
    """
    Helper function to validate params, and prepare error dictionary
    """
    for expected_arg in expected_args_list:
        expected_arg_value = runner_utils.get_param_for_module(block_id, block_dict, expected_arg)
        if not isinstance(expected_arg_value, int) and not expected_arg_value:
            error_dict[expected_arg] = 'No {0} provided for block_id: {1}'.format(expected_arg, block_id)


def get_filtered_params_to_log(block_id, block_dict, extra_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "/some/path/file.txt", 'status': True},
                  'caller': 'Audit'}
    """
    log.debug('get_filtered_params_to_log for id: {0}'.format(block_id))
    # fetch required param
    function_name = runner_utils.get_param_for_module(block_id, block_dict, 'function')

    return {'function_name': function_name}


def execute(block_id, block_dict, extra_args=None):
    """
    Execute the module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "/some/path/file.txt", 'status': True},
                  'caller': 'Audit'}

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing misc module for id: {0}'.format(block_id))

    function_name = runner_utils.get_param_for_module(block_id, block_dict, 'function')

    result = FUNCTION_MAP[function_name](block_id, block_dict, extra_args)

    if result is True:
        return runner_utils.prepare_positive_result_for_module(block_id, True)
    return runner_utils.prepare_negative_result_for_module(block_id, result)

def _check_all_ports_firewall_rules(block_id, block_dict, extra_args):
    """
    Ensure firewall rule for all open ports
    """
    start_open_ports = (_execute_shell_command('netstat -ln | grep "Active Internet connections (only servers)" -n | cut -d ":" -f1', python_shell=True)).strip()
    end_open_ports = (_execute_shell_command('netstat -ln | grep "Active UNIX domain sockets (only servers)" -n  | cut -d ":" -f1', python_shell=True)).strip()
    open_ports = (_execute_shell_command('netstat -ln | awk \'FNR > ' + start_open_ports + ' && FNR < ' + end_open_ports + ' && $6 == "LISTEN" && $4 !~ /127.0.0.1/ {print $4}\' | sed -e "s/.*://"', python_shell=True)).strip()
    open_ports = open_ports.split('\n') if open_ports != "" else []
    firewall_ports = (_execute_shell_command('iptables -L INPUT -v -n | awk \'FNR > 2 && $11 != "" && $11 ~ /^dpt:/ {print $11}\' | sed -e "s/.*://"', python_shell=True)).strip()
    firewall_ports = firewall_ports.split('\n') if firewall_ports != "" else []
    no_firewall_ports = []

    for open_port in open_ports:
        if open_port not in firewall_ports:
            no_firewall_ports.append(open_port)

    return True if len(no_firewall_ports) == 0 else str(no_firewall_ports)

def _check_password_fields_not_empty(block_id, block_dict, extra_args):
    """
    Ensure password fields are not empty
    """
    result = _execute_shell_command('cat /etc/shadow | awk -F: \'($2 == "" ) { print $1 " does not have a password "}\'', python_shell=True)
    return True if result == '' else result

def _system_account_non_login(block_id, block_dict, extra_args=None):
    """
    Ensure system accounts are non-login
    """
    non_login_shell = runner_utils.get_param_for_module(block_id, block_dict, 'non_login_shell', '/sbin/nologin')
    max_system_uid = runner_utils.get_param_for_module(block_id, block_dict, 'max_system_uid', '500')
    except_for_users = runner_utils.get_param_for_module(block_id, block_dict, 'except_for_users', '')

    users_list = ['root','halt','sync','shutdown']
    for user in except_for_users.split(","):
        if user.strip() != "":
            users_list.append(user.strip())
    result = []
    cmd = __mods__["cmd.run_all"]('egrep -v "^\+" /etc/passwd ')
    for line in cmd['stdout'].split('\n'):
        tokens = line.split(':')
        if tokens[0] not in users_list and int(tokens[2]) < int(max_system_uid) and tokens[6] not in ( non_login_shell , "/bin/false" ):
           result.append(line)
    return True if result == [] else str(result)

def _default_group_for_root(block_id, block_dict, extra_args):
    """
    Ensure default group for the root account is GID 0
    """
    result = _execute_shell_command('grep "^root:" /etc/passwd | cut -f4 -d:', python_shell=True)
    result = result.strip()
    return True if result == '0' else False


def _root_is_only_uid_0_account(block_id, block_dict, extra_args):
    """
    Ensure root is the only UID 0 account
    """
    result = _execute_shell_command('cat /etc/passwd | awk -F: \'($3 == 0) { print $1 }\'', python_shell=True)
    return True if result.strip() == 'root' else result

def _check_time_synchronization(block_id, block_dict, extra_args):
    """
    Ensure that some service is running to synchronize the system clock
    """
    command = 'systemctl status systemd-timesyncd ntpd | grep "Active: active (running)"'
    output = _execute_shell_command(command, python_shell=True)
    if output.strip() == '':
        return "neither ntpd nor timesyncd is running"
    else:
        return True

def _check_path_integrity(block_id, block_dict, extra_args):
    """
    Ensure that system PATH variable is not malformed.
    """

    script = """
    if [ "`echo $PATH | grep ::`" != "" ]; then
        echo "Empty Directory in PATH (::)"
    fi

    if [ "`echo $PATH | grep :$`" != "" ]; then
        echo "Trailing : in PATH"
    fi

    p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
    set -- $p
    while [ "$1" != "" ]; do
        if [ "$1" = "." ]; then
            echo "PATH contains ."
            shift
            continue
        fi

        if [ -d $1 ]; then
            dirperm=`ls -ldH $1 | cut -f1 -d" "`
            if [ `echo $dirperm | cut -c6` != "-" ]; then
                echo "Group Write permission set on directory $1"
            fi
            if [ `echo $dirperm | cut -c9` != "-" ]; then
                echo "Other Write permission set on directory $1"
            fi
            dirown=`ls -ldH $1 | awk '{print $3}'`
            if [ "$dirown" != "root" ] ; then
                echo $1 is not owned by root
            fi
            else
            echo $1 is not a directory
        fi
        shift
    done

    """
    output = _execute_shell_command(script, python_shell=True)
    return True if output.strip() == '' else output

def _check_duplicate_uids(block_id, block_dict, extra_args):
    """
    Return False if any duplicate user id exist in /etc/group file, else return True
    """
    uids = _execute_shell_command("cat /etc/passwd | cut -f3 -d\":\"", python_shell=True).strip()
    uids = uids.split('\n') if uids != "" else []
    duplicate_uids = [k for k, v in Counter(uids).items() if v > 1]
    if duplicate_uids is None or duplicate_uids == []:
        return True
    return str(duplicate_uids)

def _check_duplicate_gids(block_id, block_dict, extra_args):
    """
    Return False if any duplicate group id exist in /etc/group file, else return True
    """
    gids = _execute_shell_command("cat /etc/group | cut -f3 -d\":\"", python_shell=True).strip()
    gids = gids.split('\n') if gids != "" else []
    duplicate_gids = [k for k, v in Counter(gids).items() if v > 1]
    if duplicate_gids is None or duplicate_gids == []:
        return True
    return str(duplicate_gids)

def _check_duplicate_unames(block_id, block_dict, extra_args):
    """
    Return False if any duplicate user names exist in /etc/group file, else return True
    """
    unames = _execute_shell_command("cat /etc/passwd | cut -f1 -d\":\"", python_shell=True).strip()
    unames = unames.split('\n') if unames != "" else []
    duplicate_unames = [k for k, v in Counter(unames).items() if v > 1]
    if duplicate_unames is None or duplicate_unames == []:
        return True
    return str(duplicate_unames)

def _check_duplicate_gnames(block_id, block_dict, extra_args):
    """
    Return False if any duplicate group names exist in /etc/group file, else return True
    """
    gnames = _execute_shell_command("cat /etc/group | cut -f1 -d\":\"", python_shell=True).strip()
    gnames = gnames.split('\n') if gnames != "" else []
    duplicate_gnames = [k for k, v in Counter(gnames).items() if v > 1]
    if duplicate_gnames is None or duplicate_gnames == []:
        return True
    return str(duplicate_gnames)

def _check_directory_files_permission(block_id, block_dict, extra_args=None):
    """
    Check all files permission inside a directory
    """
    path = runner_utils.get_param_for_module(block_id, block_dict, 'path')
    permission = runner_utils.get_param_for_module(block_id, block_dict, 'permission')

    blacklisted_characters = '[^a-zA-Z0-9-_/]'
    if "-exec" in path or re.findall(blacklisted_characters, path):
      raise CommandExecutionError("Profile parameter '{0}' not a safe pattern".format(path))
    files_list = _execute_shell_command("find {0} -type f".format(path)).strip()
    files_list = files_list.split('\n') if files_list != "" else []
    bad_permission_files = []
    for file_in_directory in files_list:
        per = _compare_file_stats(block_id, file_in_directory, permission, True)
        if per is not True:
            bad_permission_files += [file_in_directory + ": Bad Permission - " + per + ":"]
    return True if bad_permission_files == [] else str(bad_permission_files)

def _compare_file_stats(block_id, path, permission, allow_more_strict=False):
    path_details = __mods__['file.stats'](path)

    comparator_args = {
        "type": "file_permission",
        "match": {
            "required_value": permission,
            "allow_more_strict": allow_more_strict
        }
    }

    ret_status, ret_val = hubblestack.module_runner.comparator.run(
        block_id, comparator_args, path_details.get('mode'))
    return True if ret_status else path_details.get('mode')

def _check_core_dumps(block_id, block_dict, extra_args):
    """
    Ensure core dumps are restricted
    """
    hard_core_dump_value = _execute_shell_command("grep -R -E \"hard +core\" /etc/security/limits.conf /etc/security/limits.d/ | awk '{print $4}'", python_shell=True).strip()
    hard_core_dump_value = hard_core_dump_value.split('\n') if hard_core_dump_value != "" else []
    if '0' in hard_core_dump_value:
        return True

    if hard_core_dump_value is None or hard_core_dump_value == [] or hard_core_dump_value == "":
        return "'hard core' not found in any file"

    return str(hard_core_dump_value)

def _check_service_status(block_id, block_dict, extra_args=None):
    """
    Ensure that the given service is in the required state. Return False if it is not in desired state
    Return True otherwise
    state can be enabled or disabled.
    """
    service_name = runner_utils.get_param_for_module(block_id, block_dict, 'service_name')
    state = runner_utils.get_param_for_module(block_id, block_dict, 'state')

    all_services = __mods__['cmd.run']('systemctl list-unit-files')
    if re.search(service_name, all_services, re.M):
        output = __mods__['cmd.retcode']('systemctl is-enabled ' + service_name, ignore_retcode=True)
        if (state == "disabled" and str(output) == "1") or (state == "enabled" and str(output) == "0"):
            return True
        else:
            return __mods__['cmd.run_stdout']('systemctl is-enabled ' + service_name, ignore_retcode=True)
    else:
        if state == "disabled":
            return True
        else:
            return 'Looks like ' + service_name + ' does not exists. Please check.'

def _check_ssh_timeout_config(block_id, block_dict, extra_args):
    """
    Ensure SSH Idle Timeout Interval is configured
    """

    client_alive_interval = _execute_shell_command("grep \"^ClientAliveInterval\" /etc/ssh/sshd_config | awk '{print $NF}'", python_shell=True).strip()
    if client_alive_interval != '' and int(client_alive_interval) <= 300:
        client_alive_count_max = _execute_shell_command("grep \"^ClientAliveCountMax\" /etc/ssh/sshd_config | awk '{print $NF}'", python_shell=True).strip()
        if client_alive_count_max != '' and int(client_alive_count_max) <= 3:
            return True
        else:
            return "ClientAliveCountMax value should be less than equal to 3"
    else:
        return "ClientAliveInterval value should be less than equal to 300"

def _check_all_users_home_directory(block_id, block_dict, extra_args=None):
    """
    Ensure all users' home directories exist
    """
    max_system_uid = runner_utils.get_param_for_module(block_id, block_dict, 'max_system_uid')
    max_system_uid = int(max_system_uid)
    users_uids_dirs = _execute_shell_command("cat /etc/passwd | awk -F: '{ print $1 \" \" $3 \" \" $6 \" \" $7}'", python_shell=True).strip()
    users_uids_dirs = users_uids_dirs.split('\n') if users_uids_dirs else []
    error = []
    for user_data in users_uids_dirs:
        user_uid_dir = user_data.strip().split(" ")
        if len(user_uid_dir) < 4:
                user_uid_dir = user_uid_dir + [''] * (4 - len(user_uid_dir))
        if user_uid_dir[1].isdigit():
            if not _is_valid_home_directory(user_uid_dir[2], True) and int(user_uid_dir[1]) >= max_system_uid and user_uid_dir[0] != "nfsnobody" \
                    and 'nologin' not in user_uid_dir[3] and 'false' not in user_uid_dir[3]:
                error += ["Either home directory " + user_uid_dir[2] + " of user " + user_uid_dir[0] + " is invalid or does not exist."]
        else:
            error += ["User " + user_uid_dir[0] + " has invalid uid " + user_uid_dir[1]]
    return True if not error else str(error)

def _check_users_home_directory_permissions(block_id, block_dict, extra_args=None):
    """
    Ensure users' home directories permissions are 750 or more restrictive
    """
    max_allowed_permission = runner_utils.get_param_for_module(block_id, block_dict, 'max_allowed_permission', 750)
    except_for_users = runner_utils.get_param_for_module(block_id, block_dict, 'except_for_users', '')

    users_list = ['root','halt','sync','shutdown']
    for user in except_for_users.split(","):
        if user.strip() != "":
            users_list.append(user.strip())

    users_dirs = []
    cmd = __mods__["cmd.run_all"]('egrep -v "^\+" /etc/passwd ')
    for line in cmd['stdout'].split('\n'):
        tokens = line.split(':')
        if tokens[0] not in users_list and 'nologin' not in tokens[6] and 'false' not in tokens[6]:
            users_dirs.append(tokens[0] + " " + tokens[5])
    error = []
    for user_dir in users_dirs:
        user_dir = user_dir.split(" ")
        if len(user_dir) < 2:
                user_dir = user_dir + [''] * (2 - len(user_dir))
        if _is_valid_home_directory(user_dir[1]):
            result = _compare_file_stats(block_id, user_dir[1], max_allowed_permission, False)
            if result is not True:
                error += ["permission on home directory " + user_dir[1] + " of user " + user_dir[0] + " is wrong: " + result]

    return True if error == [] else str(error)

def _is_valid_home_directory(directory_path, check_slash_home=False):
    directory_path = None if directory_path is None else directory_path.strip()
    if directory_path is not None and directory_path != "" and os.path.isdir(directory_path):
        if check_slash_home and directory_path == "/":
            return False
        else:
            return True

    return False

def _check_users_own_their_home(block_id, block_dict, extra_args=None):
    """
    Ensure users own their home directories
    """
    max_system_uid = runner_utils.get_param_for_module(block_id, block_dict, 'max_system_uid')
    max_system_uid = int(max_system_uid)

    users_uids_dirs = _execute_shell_command("cat /etc/passwd | awk -F: '{ print $1 \" \" $3 \" \" $6 \" \" $7}'", python_shell=True).strip()
    users_uids_dirs = users_uids_dirs.split('\n') if users_uids_dirs != "" else []
    error = []
    for user_data in users_uids_dirs:
        user_uid_dir = user_data.strip().split(" ")
        if len(user_uid_dir) < 4:
            user_uid_dir = user_uid_dir + [''] * (4 - len(user_uid_dir))
        if user_uid_dir[1].isdigit():
            if not _is_valid_home_directory(user_uid_dir[2]):
                if int(user_uid_dir[1]) >= max_system_uid and 'nologin' not in user_uid_dir[3] and 'false' not in user_uid_dir[3]:
                    error += ["Either home directory " + user_uid_dir[2] + " of user " + user_uid_dir[0] + " is invalid or does not exist."]
            elif int(user_uid_dir[1]) >= max_system_uid and user_uid_dir[0] != "nfsnobody" and 'nologin' not in user_uid_dir[3] \
                    and 'false' not in user_uid_dir[3]:
                owner = __mods__['cmd.run']("stat -L -c \"%U\" \"" + user_uid_dir[2] + "\"")
                if owner != user_uid_dir[0]:
                    error += ["The home directory " + user_uid_dir[2] + " of user " + user_uid_dir[0] + " is owned by " + owner]
        else:
            error += ["User " + user_uid_dir[0] + " has invalid uid " + user_uid_dir[1]]

    return True if not error else str(error)

def _check_users_dot_files(block_id, block_dict, extra_args):
    """
    Ensure users' dot files are not group or world writable
    """

    users_dirs = _execute_shell_command("cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != \"/sbin/nologin\") {print $1\" \"$6}'", python_shell=True).strip()
    users_dirs = users_dirs.split('\n') if users_dirs != "" else []
    error = []
    for user_dir in users_dirs:
        user_dir = user_dir.split()
        if len(user_dir) < 2:
                user_dir = user_dir + [''] * (2 - len(user_dir))
        if _is_valid_home_directory(user_dir[1]):
            dot_files = _execute_shell_command("find " + user_dir[1] + " -name \".*\"").strip()
            dot_files = dot_files.split('\n') if dot_files != "" else []
            for dot_file in dot_files:
                if os.path.isfile(dot_file):
                    path_details = __mods__['file.stats'](dot_file)
                    given_permission = path_details.get('mode')
                    file_permission = given_permission[-3:]
                    if file_permission[1] in ["2", "3", "6", "7"]:
                        error += ["Group Write permission set on file " + dot_file + " for user " + user_dir[0]]
                    if file_permission[2] in ["2", "3", "6", "7"]:
                        error += ["Other Write permission set on file " + dot_file + " for user " + user_dir[0]]

    return True if error == [] else str(error)

def _check_users_forward_files(block_id, block_dict, extra_args):
    """
    Ensure no users have .forward files
    """

    users_dirs = _execute_shell_command("cat /etc/passwd | awk -F: '{ print $1\" \"$6 }'", python_shell=True).strip()
    users_dirs = users_dirs.split('\n') if users_dirs != "" else []
    error = []
    for user_dir in users_dirs:
        user_dir = user_dir.split()
        if len(user_dir) < 2:
                user_dir = user_dir + [''] * (2 - len(user_dir))
        if _is_valid_home_directory(user_dir[1]):
            forward_file = _execute_shell_command("find " + user_dir[1] + " -maxdepth 1 -name \".forward\"").strip()
            if forward_file is not None and os.path.isfile(forward_file):
                error += ["Home directory: " + user_dir[1] + ", for user: " + user_dir[0] + " has " + forward_file + " file"]

    return True if error == [] else str(error)

def _check_users_netrc_files(block_id, block_dict, extra_args):
    """
    Ensure no users have .netrc files
    """

    users_dirs = _execute_shell_command("cat /etc/passwd | awk -F: '{ print $1\" \"$6 }'", python_shell=True).strip()
    users_dirs = users_dirs.split('\n') if users_dirs != "" else []
    error = []
    for user_dir in users_dirs:
        user_dir = user_dir.split()
        if len(user_dir) < 2:
                user_dir = user_dir + [''] * (2 - len(user_dir))
        if _is_valid_home_directory(user_dir[1]):
            netrc_file = _execute_shell_command("find " + user_dir[1] + " -maxdepth 1 -name \".netrc\"").strip()
            if netrc_file is not None and os.path.isfile(netrc_file):
                error += ["Home directory: " + user_dir[1] + ", for user: " + user_dir[0] + " has .netrc file"]

    return True if error == [] else str(error)

def _check_groups_validity(block_id, block_dict, extra_args):
    """
    Ensure all groups in /etc/passwd exist in /etc/group
    """

    group_ids_in_passwd = _execute_shell_command("cut -s -d: -f4 /etc/passwd 2>/dev/null", python_shell=True).strip()
    group_ids_in_passwd = group_ids_in_passwd.split('\n') if group_ids_in_passwd != "" else []
    group_ids_in_passwd = list(set(group_ids_in_passwd))
    invalid_groups = []
    for group_id in group_ids_in_passwd:
        group_presence_validity = _execute_shell_command("getent group " + group_id + " 2>/dev/null 1>/dev/null; echo $?", python_shell=True).strip()
        if str(group_presence_validity) != "0":
            invalid_groups += ["Invalid groupid: " + group_id + " in /etc/passwd file"]

    return True if invalid_groups == [] else str(invalid_groups)

def _ensure_reverse_path_filtering(block_id, block_dict, extra_args):
    """
    Ensure Reverse Path Filtering is enabled
    """
    error_list = []
    command = "sysctl net.ipv4.conf.all.rp_filter 2> /dev/null"
    output = _execute_shell_command(command, python_shell=True)
    if output.strip() == '':
        error_list.append("net.ipv4.conf.all.rp_filter not found")
    search_results = re.findall("rp_filter = (\d+)", output)
    result = int(search_results[0])
    if result < 1:
        error_list.append("net.ipv4.conf.all.rp_filter  value set to " + str(result))
    command = "sysctl net.ipv4.conf.default.rp_filter 2> /dev/null"
    output = _execute_shell_command(command, python_shell=True)
    if output.strip() == '':
        error_list.append("net.ipv4.conf.default.rp_filter not found")
    search_results = re.findall("rp_filter = (\d+)", output)
    result = int(search_results[0])
    if result < 1:
        error_list.append("net.ipv4.conf.default.rp_filter  value set to " + str(result))
    if len(error_list) > 0:
        return str(error_list)
    else:
        return True

def _check_users_rhosts_files(block_id, block_dict, extra_args):
    """
    Ensure no users have .rhosts files
    """

    users_dirs = _execute_shell_command("cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != \"/sbin/nologin\") {print $1\" \"$6}'", python_shell=True).strip()
    users_dirs = users_dirs.split('\n') if users_dirs != "" else []
    error = []
    for user_dir in users_dirs:
        user_dir = user_dir.split()
        if len(user_dir) < 2:
            user_dir = user_dir + [''] * (2 - len(user_dir))
        if _is_valid_home_directory(user_dir[1]):
            rhosts_file = _execute_shell_command("find " + user_dir[1] + " -maxdepth 1 -name \".rhosts\"").strip()
            if rhosts_file is not None and os.path.isfile(rhosts_file):
                error += ["Home directory: " + user_dir[1] + ", for user: " + user_dir[0] + " has .rhosts file"]
    return True if error == [] else str(error)

def _check_netrc_files_accessibility(block_id, block_dict, extra_args):
    """
    Ensure users' .netrc Files are not group or world accessible
    """

    script = """
    for dir in `cat /etc/passwd | egrep -v '(root|sync|halt|shutdown)' | awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
      for file in $dir/.netrc; do
        if [ ! -h "$file" -a -f "$file" ]; then
          fileperm=`ls -ld $file | cut -f1 -d" "`
          if [ `echo $fileperm | cut -c5` != "-" ]; then
            echo "Group Read set on $file"
          fi
          if [ `echo $fileperm | cut -c6` != "-" ]; then
            echo "Group Write set on $file"
          fi
          if [ `echo $fileperm | cut -c7` != "-" ]; then
            echo "Group Execute set on $file"
          fi
          if [ `echo $fileperm | cut -c8` != "-" ]; then
            echo "Other Read set on $file"
          fi
          if [ `echo $fileperm | cut -c9` != "-" ]; then
            echo "Other Write set on $file"
          fi
          if [ `echo $fileperm | cut -c10` != "-" ]; then
            echo "Other Execute set on $file"
          fi
        fi
      done
    done

    """
    output = _execute_shell_command(script, python_shell=True)
    return True if output.strip() == '' else output


def _grep(path,
          pattern,
          *args):
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
        options = ' '.join(args)
    else:
        options = ''
    cmd = (
        r'''grep {options} {pattern} {path}'''
        .format(
            options=options,
            pattern=pattern,
            path=path,
        )
    )

    try:
        log.info(cmd)
        ret = __salt__['cmd.run_all'](cmd, python_shell=False, ignore_retcode=True)
    except (IOError, OSError) as exc:
        raise CommandExecutionError(exc.strerror)

    return ret


def _check_list_values(block_id, block_dict, extra_args=None):
    """
    This function will first get the line matching given match_pattern.
    After this value pattern will be extracted from the above line.
    value pattern will be splitted by value_delimiter to get the list of values.
    match_pattern will be regex patter for grep command.
    value_pattern will be regex for re module of python to get matched values.
    Only one of white_list and blacklist is allowed.
    white_list and black_list should have comma(,) seperated values.

    audit profile example:

sshd_hostbased_auth_coreos:
  description: 'Ensure SSH HostbasedAuthentication is disabled'
  tag: 'test1'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      module: misc
      items:
        - args:
            function: check_list_values
            file_path: /srv/hubble/hubblestack_audit_profiles/ssh_config
            match_pattern: '^restrict.*default'
            value_pattern: '^restrict.*default(.*)$'
            grep_arg: null
            white_list: kod,nomodify,notrap,nopeer,noquery
            black_list: null
            value_delimter: ' '
          comparator:
            type: "boolean"
            match: true
    """
    file_path = runner_utils.get_param_for_module(block_id, block_dict, 'file_path')
    match_pattern = runner_utils.get_param_for_module(block_id, block_dict, 'match_pattern')
    value_pattern = runner_utils.get_param_for_module(block_id, block_dict, 'value_pattern')
    grep_arg = runner_utils.get_param_for_module(block_id, block_dict, 'grep_arg')
    white_list = runner_utils.get_param_for_module(block_id, block_dict, 'white_list')
    black_list = runner_utils.get_param_for_module(block_id, block_dict, 'black_list')
    value_delimter = runner_utils.get_param_for_module(block_id, block_dict, 'value_delimter')

    list_delimter = ","

    if black_list is not None and white_list is not None:
        return "Both black_list and white_list values are not allowed."
    grep_args = [] if grep_arg is None else [grep_arg]
    matched_lines = _grep(file_path, match_pattern, *grep_args).get('stdout')
    if not matched_lines:
        return "No match found for the given pattern: " + str(match_pattern)

    matched_lines = matched_lines.split('\n') if matched_lines is not None else []
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

def _mail_conf_check(block_id, block_dict, extra_args):
    """
    Ensure mail transfer agent is configured for local-only mode
    """
    valid_addresses = ["localhost", "127.0.0.1", "::1"]
    mail_addresses = _execute_shell_command("grep '^[[:blank:]]*inet_interfaces' /etc/postfix/main.cf | awk -F'=' '{print $2}'", python_shell=True).strip()
    mail_addresses = str(mail_addresses)
    mail_addresses = mail_addresses.split(',') if mail_addresses != "" else []
    mail_addresses = list(map(str.strip, mail_addresses))
    invalid_addresses = list(set(mail_addresses) - set(valid_addresses))

    return str(invalid_addresses) if invalid_addresses != [] else True

def _ensure_max_password_expiration(block_id, block_dict, extra_args=None):
    """
    Ensure max password expiration days is set to the value less than or equal to that given in args
    """
    allow_max_days = runner_utils.get_param_for_module(block_id, block_dict, 'allow_max_days')
    except_for_users = runner_utils.get_param_for_module(block_id, block_dict, 'except_for_users', '')

    grep_args = []
    pass_max_days_output = _grep('/etc/login.defs', '^PASS_MAX_DAYS', *grep_args).get('stdout')
    if not pass_max_days_output:
        return "PASS_MAX_DAYS must be set"
    system_pass_max_days = pass_max_days_output.split()[1]

    if not _is_int(system_pass_max_days):
        return "PASS_MAX_DAYS must be set properly"
    if int(system_pass_max_days) > allow_max_days:
        return "PASS_MAX_DAYS must be less than or equal to " + str(allow_max_days)

    #fetch all users with passwords
    grep_args.append('-E')
    all_users = _grep('/etc/shadow', '^[^:]+:[^\!*]', *grep_args).get('stdout')

    except_for_users_list=[]
    for user in except_for_users.split(","):
        if user.strip() != "":
            except_for_users_list.append(user.strip())
    result = []
    for line in all_users.split('\n'):
        user = line.split(':')[0]
        #As per CIS doc, 5th field is the password max expiry days
        user_passwd_expiry = line.split(':')[4]
        if not user in except_for_users_list and _is_int(user_passwd_expiry) and int(user_passwd_expiry) > allow_max_days:
            result.append('User ' + user + ' has max password expiry days ' + user_passwd_expiry + ', which is more than ' + str(allow_max_days))

    return True if result == [] else str(result)

def _is_int(input):
    try:
        num = int(input)
    except ValueError:
        return False
    return True

def _check_sshd_parameters(block_id, block_dict, extra_args=None):
    """
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
    pattern = runner_utils.get_param_for_module(block_id, block_dict, 'pattern')
    values = runner_utils.get_param_for_module(block_id, block_dict, 'values')
    comparetype = runner_utils.get_param_for_module(block_id, block_dict, 'comparetype', 'regex')

    output = __mods__['cmd.run']('sshd -T')
    if comparetype == 'only':
        if not values:
            return "You need to provide values for comparetype 'only'."
        else:
            for line in output.splitlines():
                if re.match(pattern, line, re.I):
                    expected_values = values.split(',')
                    found_values = line[len(pattern):].strip().split(',')
                    for found_value in found_values:
                        if found_value in expected_values:
                            continue
                        else:
                            return "Allowed values for pattern: " + pattern + " are " + values
                    return True
            return "Looks like pattern i.e. " + pattern + " not found in sshd -T. Please check."
    elif comparetype == 'regex':
        if re.search(pattern, output, re.M | re.I):
            return True
        else:
            return "Looks like pattern i.e. " + pattern + " not found in sshd -T. Please check."
    else:
        return "The comparetype: " + comparetype + " not found. It can be 'regex' or 'only'. Please check."

def _test_success(block_id, block_dict, extra_args):
    """
    Automatically returns success
    """
    return True


def _test_failure(block_id, block_dict, extra_args):
    """
    Automatically returns failure, no reason
    """
    return False


def _test_failure_reason(block_id, block_dict, extra_args):
    """
    Automatically returns failure, with a reason
    """
    return runner_utils.get_param_for_module(block_id, block_dict, 'reason')

def _execute_shell_command(cmd, python_shell=False):
    """
    This function will execute passed command in /bin/shell
    """
    return __mods__['cmd.run'](cmd, python_shell=python_shell, shell='/bin/bash', ignore_retcode=True)


FUNCTION_MAP = {
    'check_all_ports_firewall_rules': _check_all_ports_firewall_rules,
    'check_password_fields_not_empty': _check_password_fields_not_empty,
    'system_account_non_login': _system_account_non_login,
    'default_group_for_root': _default_group_for_root,
    'root_is_only_uid_0_account': _root_is_only_uid_0_account,
    'test_success': _test_success,
    'test_failure': _test_failure,
    'test_failure_reason': _test_failure_reason,
    'check_path_integrity': _check_path_integrity,
    'check_time_synchronization': _check_time_synchronization,
    'check_core_dumps': _check_core_dumps,
    'check_directory_files_permission': _check_directory_files_permission,
    'check_duplicate_gnames': _check_duplicate_gnames,
    'check_duplicate_unames': _check_duplicate_unames,
    'check_duplicate_gids': _check_duplicate_gids,
    'check_duplicate_uids': _check_duplicate_uids,
    'check_service_status': _check_service_status,
    'check_ssh_timeout_config': _check_ssh_timeout_config,
    'check_all_users_home_directory': _check_all_users_home_directory,
    'check_users_home_directory_permissions': _check_users_home_directory_permissions,
    'check_users_own_their_home': _check_users_own_their_home,
    'check_users_dot_files': _check_users_dot_files,
    'check_users_forward_files': _check_users_forward_files,
    'check_users_netrc_files': _check_users_netrc_files,
    'check_groups_validity': _check_groups_validity,
    'ensure_reverse_path_filtering': _ensure_reverse_path_filtering,
    'check_users_rhosts_files': _check_users_rhosts_files,
    'check_netrc_files_accessibility': _check_netrc_files_accessibility,
    'check_list_values': _check_list_values,
    'mail_conf_check': _mail_conf_check,
    'ensure_max_password_expiration': _ensure_max_password_expiration,
    'check_sshd_parameters': _check_sshd_parameters,
}