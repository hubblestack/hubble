# -*- encoding: utf-8 -*-
"""
Module for running pkg command. Same can be used in both Audit/FDG

Audit Example:
---------------
check_unique_id:
  description: 'pkg check'
  tag: 'ADOBE-01'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      module: pkg
      items:
        - args:
            name: perl*

FDG Example:
------------
main:
  description: 'pkg check'
  module: pkg
  args:
    name: perl*
Mandatory parameters:
    name - name of package
Multiple package names can be provided in a single implementation under attribute: "items"

Note: Comparison logic is moved to comparators. Module will just invoke the pkg command.
Comparator compatible with this module - dict

Sample Output:
{
    'perl-srpm-macros': '1-8.el7',
    'perl-parent': '1:0.225-244.el7',
    'perl-podlators': '2.5.1-3.el7',
    'perl-Pod-Escapes': '1:1.04-295.el7',
    'perl-Encode': '2.51-7.el7'
}
"""

import logging
import fnmatch

import hubblestack.extmods.module_runner.runner_utils as runner_utils
from hubblestack.utils.hubble_error import HubbleCheckValidationError

log = logging.getLogger(__name__)


def validate_params(block_id, block_dict, chain_args=None):
    """
    Validate all mandatory params required for this module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param chain_args:
        Chained argument dictionary, (If any)
        Example: {'result': "/some/path/file.txt", 'status': True}

    Raises:
        AuditCheckValidationError: For any validation error
    """
    log.debug('Module: pkg Start validating params for check-id: {0}'.format(block_id))

    # fetch required param
    mandatory_params = ['name']
    error = {}
    for param in mandatory_params:
        param_val = runner_utils.get_param_for_module(block_id, block_dict, param, chain_args)
        if not param_val:
            error[param] = 'Mandatory parameter: %s not found for id: %s' % (param, block_id)

    if error:
        raise HubbleCheckValidationError(error)

    log.debug('Validation success for check-id: {0}'.format(block_id))


def execute(block_id, block_dict, chain_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param chain_args:
        Chained argument dictionary, (If any)
        Example: {'result': {'test-package': '1.2.3'}, 'status': True}

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing pkg module for id: {0}'.format(block_id))

    # fetch required param
    name = runner_utils.get_param_for_module(block_id, block_dict, 'name', chain_args)

    installed_pkgs_dict = __salt__['pkg.list_pkgs']()
    filtered_pkgs_list = fnmatch.filter(installed_pkgs_dict, name)
    result_dict = {}
    for package in filtered_pkgs_list:
        result_dict[package] = installed_pkgs_dict[package]

    return runner_utils.prepare_positive_result_for_module(block_id, result_dict)


def get_filtered_params_to_log(block_id, block_dict, chain_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param chain_args:
        Chained argument dictionary, (If any)
        Example: {'result': {'test-package': '1.2.3'}, 'status': True}
    """
    log.debug('get_filtered_params_to_log for id: {0}'.format(block_id))

    # fetch required param
    name = runner_utils.get_param_for_module(block_id, block_dict, 'name', chain_args)

    return {'name': name}