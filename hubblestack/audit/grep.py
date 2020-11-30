# -*- encoding: utf-8 -*-
"""
Grep module for running grep command. 
Same can be used in both Audit/FDG

Note: Now each module just returns its output (As Data gathering)
      For Audit checks, comparison logic is now moved to comparators. 
      See below sections for more understanding

Usable in Modules
-----------------
- Audit
- FDG

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

FDG Schema
----------
FDG schema is kept simple. Only following keywords allowed:
- Unique id
    Unique string id
- description (Optional)
    Some description
- module
    Name of the module
- args
    Module arguments
- comparator (Only in case of Audit-FDG connector)

FDG Chaining
------------
In normal execution, this module expects a filepath. 
In case of chaining, it expects a string from the chained parameter

Module Arguments
----------------
- path
    Path of source file
    Multiple paths can be provided in a single implementation under attribute: "items"
    
    If used in chaining, this parameter can be removed as input will come from 
    the chaining parameter.
- pattern
    Pattern to search
- flags (Optional)
    Array of grep command arguments

Module Output
-------------
String as output of grep command. It can be multiline as well depending upon the result
Example: "Sample grep output\nanother line"

Output: (True, "Sample grep output\nanother line")
Note: Module returns a tuple
    First value being the status of module
    Second value is the actual output from module

Compatible Comparators
----------------------
Since output is pretty dynamic. Following comparators can be used:
- string (Will be used mostly used along with grep module)
- boolean
- list
- dict
- number

For detailed documentation on comparators,
read comparator's implementations at (/hubblestack/extmods/comparators/)


Audit Example
---------------
check_unique_id:
  description: 'grep check'
  tag: 'ADOBE-01'
  sub_check: false (Optional, default: false)
  failure_reason: 'a sample failure reason' (Optional)
  invert_result: false (Optional, default: false)
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      # return_no_exec: true (Optional, default: false)
      check_eval_logic: and (Optional, default: and)
      module: grep
      items:
        - args:
            path: /etc/ssh/ssh_config
            pattern: '"^host"'
            flags: 
                - '-E'
          comparator:
            type: "string"
            match: "host*"
            is_regex: true

FDG Example:
------------
main:
  description: 'sample description'
  module: grep
  args:
    path: /etc/ssh/ssh_config
    pattern: 'host'

"""

import os
import logging

import hubblestack.module_runner.runner_utils as runner_utils
from hubblestack.exceptions import HubbleCheckValidationError, CommandExecutionError

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
    log.debug('Module: grep Start validating params for check-id: {0}'.format(block_id))

    error = {}
    # fetch required param
    file_content = runner_utils.get_chained_param(extra_args)
    if not file_content:
        filepath = runner_utils.get_param_for_module(block_id, block_dict, 'path')
    if not file_content and not filepath:
        error['path'] = 'Mandatory parameter: path not found for id: %s' % (block_id)

    pattern_val = runner_utils.get_param_for_module(block_id, block_dict, 'pattern')
    if not pattern_val:
        error['pattern'] = 'Mandatory parameter: pattern not found for id: %s' % (block_id)

    if error:
        raise HubbleCheckValidationError(error)

    log.debug('Validation success for check-id: {0}'.format(block_id))


def execute(block_id, block_dict, extra_args=None):
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

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing grep module for id: {0}'.format(block_id))
    # default mode=file, search in file.
    # In chaining, this will search in chained content
    file_mode = True
    filepath = None

    # check if chained content is available
    file_content = runner_utils.get_chained_param(extra_args)
    if file_content:
        file_mode = False
        format_chained = runner_utils.get_param_for_module(block_id, block_dict, 'format_chained', True)
        starting_string = runner_utils.get_param_for_module(block_id, block_dict, 'starting_string', False)
        if format_chained and starting_string:
            file_content = starting_string.format(file_content)
    # fetch required param
    if file_mode:
        filepath = runner_utils.get_param_for_module(block_id, block_dict, 'path')
    pattern = runner_utils.get_param_for_module(block_id, block_dict, 'pattern')
    flags = runner_utils.get_param_for_module(block_id, block_dict, 'flags')
    if flags is None:
        flags = []
    if isinstance(flags, str):
        flags = [flags]

    # check filepath existence
    if file_mode and not os.path.isfile(filepath):
        return runner_utils.prepare_negative_result_for_module(block_id, 'file_not_found')

    grep_result = _grep(filepath, file_content, pattern, *flags)
    ret_code = grep_result.get('retcode')
    result = grep_result.get('stdout')
    log.debug("grep module output for block_id %s, is %s", block_id, result)
    if ret_code != 0:
        if ret_code == 1:
            return runner_utils.prepare_negative_result_for_module(block_id, "pattern_not_found")
        else:
            return runner_utils.prepare_negative_result_for_module(block_id, "non_zero_return_code")

    return runner_utils.prepare_positive_result_for_module(block_id, result)


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
    filepath = runner_utils.get_chained_param(extra_args)
    if not filepath:
        filepath = runner_utils.get_param_for_module(block_id, block_dict, 'path')
    pattern = runner_utils.get_param_for_module(block_id, block_dict, 'pattern')

    return {'path': filepath,
            'pattern': pattern}


def _grep(path,
          string,
          pattern,
          *args
          ):
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

    string
        String to search (Only used while chaining)

    pattern
        Pattern to match. For example: ``test``, or ``a[0-5]``

    args
        Additional command-line flags to pass to the grep command. For example:
        ``-v``, or ``-i -B2``
    """
    if path:
        path = os.path.expanduser(path)

    if args:
        options = [' '.join(args)]
    else:
        options = []

    # prepare the command
    cmd = ['grep'] + options + [pattern]
    if path:
        cmd += [path]

    try:
        ret = __mods__['cmd.run_all'](cmd, python_shell=False, ignore_retcode=True, stdin=string)
    except (IOError, OSError) as exc:
        raise CommandExecutionError(exc.strerror)

    return ret
