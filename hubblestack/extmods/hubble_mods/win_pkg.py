# -*- encoding: utf-8 -*-
"""
Module for fetching installed pkg list using salt's pkg.list_pkgs function

Audit Example 1:
---------------
check_unique_id:
  description: 'win_pkg check'
  tag: 'ADOBE-01'
  implementations:
    - filter:
        grains: 'G@osfinger:Microsoft Windows Server 2016*'
      hubble_version: '>3 AND <7 AND <8'
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
Mandatory parameters:
    name - the name of the pkg

Note: Comparison logic is moved to comparators. Module will just invoke the win_pkg command.
Comparator compatible with this module - dict, version

Sample Output:
1. dictionary with matchable value in 'package_version'
    {"package_name": 'LAPS AdmPwd GPO Extension / CSE is installed', "package_version": '6.2.0.0'}

Note: In normal execution, this module expects a security configuration name.
In case of chaining, it expects a string(pkg name) from chaining
"""
import logging
import salt.utils
import salt.utils.platform

import hubblestack.extmods.module_runner.runner_utils as runner_utils
from hubblestack.utils.hubble_error import HubbleCheckValidationError
from salt.exceptions import CommandExecutionError


log = logging.getLogger(__name__)


def __virtual__():
    if not salt.utils.platform.is_windows():
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
        __pkgdata__ = __salt__['pkg.list_pkgs']()
    except CommandExecutionError:
        __salt__['pkg.refresh_db']()
        __pkgdata__ = __salt__['pkg.list_pkgs']()
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
    chained_pkg_name = None
    chained_result = runner_utils.get_chained_param(extra_args)
    if chained_result:
        chained_pkg_name = chained_result
    pkg_name = runner_utils.get_param_for_module(block_id, block_dict, 'name')
    if not chained_pkg_name and not pkg_name:
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
