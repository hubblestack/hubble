# -*- encoding: utf-8 -*-
"""
Module for fetching installed pkg list using salt's pkg.list_pkgs function

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
In normal execution, this module expects package name
In case of chaining, it expects package name from the chained parameter

Module Arguments
----------------
- name
    the name of the pkg

Module Output
-------------
{"package_name": 'LAPS AdmPwd GPO Extension / CSE is installed', "package_version": '6.2.0.0'}

Output: (True, <Above dict>)

Note: Module returns a tuple
    First value being the status of module
    Second value is the actual output from module

Compatible Comparators
----------------------
- dict
- version

For detailed documentation on comparators,
read comparator's implementations at (/hubblestack/extmods/comparators/)

Audit Example
---------------
check_unique_id:
  description: 'win_pkg check'
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
      module: win_pkg
      items:
        - args:
            name: 'LAPS AdmPwd GPO Extension / CSE is installed'
          comparator:
            type: "dict"
            match:
              package_version:
                type: "version"
                match:
                  - '>= 6.2.0.0'

FDG Example:
------------
main:
  description: 'win_pkg fdg'
  module: win_pkg
  args:
    name: LAPS AdmPwd GPO Extension / CSE is installed
"""
import logging
import hubblestack.utils.platform

import hubblestack.module_runner.runner_utils as runner_utils
from hubblestack.exceptions import HubbleCheckValidationError
from hubblestack.exceptions import CommandExecutionError


log = logging.getLogger(__name__)


def __virtual__():
    if not hubblestack.utils.platform.is_windows():
        return False, 'This audit module only runs on windows'
    return True


def execute(block_id, block_dict, extra_args=None):
    """
    Execute the module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Chained argument dictionary, (If any)
        Example: {'chaining_args': {'result': "Local Administrator Password Solution", 'status': True},
                  'caller': 'Audit'}

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing win_pkg module for id: {0}'.format(block_id))
    try:
        __pkgdata__ = __mods__['pkg.list_pkgs']()
    except CommandExecutionError:
        __mods__['pkg.refresh_db']()
        __pkgdata__ = __mods__['pkg.list_pkgs']()
    if not __pkgdata__:
        return runner_utils.prepare_negative_result_for_module(block_id, "package list couldn't be fetched")

    chained_result = runner_utils.get_chained_param(extra_args)
    if chained_result:
        pkg_name = chained_result
    else:
        pkg_name = runner_utils.get_param_for_module(block_id, block_dict, 'name')

    if pkg_name in __pkgdata__:
        audit_value = __pkgdata__.get(pkg_name)
    else:
        log.debug("for block id %s, pkg %s is not found in pkg data", block_id, pkg_name)
        audit_value = "Not Found"

    result = {"package_name": pkg_name, "package_version": audit_value}
    log.debug("win_pkg module output for block_id %s, is %s", block_id, result)

    if not result:
        return runner_utils.prepare_negative_result_for_module(block_id, "package information couldn't be fetched")

    return runner_utils.prepare_positive_result_for_module(block_id, result)


def validate_params(block_id, block_dict, extra_args=None):
    """
        Validate all mandatory params required for this module

        :param block_id:
            id of the block
        :param block_dict:
            parameter for this module
        :param extra_args:
            Chained argument dictionary, (If any)
            Example: {'chaining_args': {'result': "Local Administrator Password Solution", 'status': True},
                  'caller': 'Audit'}

        Raises:
            HubbleCheckValidationError: For any validation error
        """
    log.debug('Module: win_pkg. Start validating params for check-id: {0}'.format(block_id))
    error = {}

    # fetch required param
    chained_result = runner_utils.get_chained_param(extra_args)
    if chained_result:
        pkg_name = chained_result.get('name')
    else:
        pkg_name = runner_utils.get_param_for_module(block_id, block_dict, 'name')

    if not pkg_name:
        error['name'] = 'Mandatory parameter: name not found for id: %s' % block_id

    if error:
        raise HubbleCheckValidationError(error)

    log.debug('Validation success for check-id: {0}'.format(block_id))


def get_filtered_params_to_log(block_id, block_dict, extra_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Chained argument dictionary, (If any)
        Example: {'chaining_args': {'result': "Local Administrator Password Solution", 'status': True},
                  'caller': 'Audit'}
    """
    log.debug('get_filtered_params_to_log for win_pkg and id: {0}'.format(block_id))

    # fetch required param
    chained_result = runner_utils.get_chained_param(extra_args)
    if chained_result:
        pkg_name = chained_result
    else:
        pkg_name = runner_utils.get_param_for_module(block_id, block_dict, 'name')

    return {'name': pkg_name}
