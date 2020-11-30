# -*- encoding: utf-8 -*-
"""
FDG Connector module for writing audit profiles with FDG.
Since chaining is only present in FDG, Audit modules can use this module to invoke a FDG profile.

This audit module requires yaml data to execute. It will search the local
directory for any .yaml files, and if it finds a top-level 'fdg' key, it will
use that data.

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
- fdg_file: 
    Path of fdg file in salt protocol.
    Example: 'salt://fdg/my_fdg_file.fdg'
- starting_chained (Optional)
    Starting value as parameter for main(first) chaining block in fdg
- true_for_success
    The ``true_for_success`` argument decides how success/failure are decided
    based on the fdg return. By default, any "truthy" value in the ``results`` piece
    of the FDG return will constitute success. Set this option to False to treat
    "falsey" values as success.
- use_status
    The ``use_status`` argument determines whether the status result or the actual
    result returned from fdg will be used. If this is True, only the status result of
    the fdg run will be considered. If it is False, only the actual result of the
    fdg run will be considered. Regardless, the ``true_for_success`` argument
    will be respected.
- consolidation_operator
    Only values allowed (and/or)
    The consolidation_operator is used when chaining is done using xpipe and the
    returned result is a list. If the list contains more than one tuple, the
    result is consolidated based on the consolidation operator.

Module Output
-------------
Output can be a boolean or any other data type. It depends upon the FDG modules being used.
Output: (True, True)

Note: Module returns a tuple
    First value being the status of module
    Second value is the actual output from module

Compatible Comparators
----------------------
Since output is pretty dynamic. Following comparators can be used:
- boolean
- string
- list
- dict
- number

For detailed documentation on comparators,
read comparator's implementations at (/hubblestack/extmods/comparators/)


Audit Example:
---------------

Sample YAML data, with inline comments:

fdg_check:   # unique ID
  description: 'sample description'
  tag: 'ADOBE-00041'
  sub_check: false (Optional, default: false)
  failure_reason: 'a sample failure reason' (Optional)
  invert_result: false (Optional, default: false)
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7' # osfinger grain
      hubble_version: '>3 AND <7 AND <8'
      # return_no_exec: true (Optional, default: false)
      check_eval_logic: and (Optional, default: and)
      module: fdg
      items:
        - args:
            fdg_file: 'salt://fdg/my_fdg_file.fdg'  # filename for fdg routine
            starting_chained: 'value'  # value for fdg `starting_chained` (optional)
            true_for_success: True  # Whether a "truth" value constitutes success
            use_status: False  # Use the status result of the fdg run.
            consolidation_operator: and/or
          comparator:
            type: boolean
            match: true
    - filter:
        grains: '*' # osfinger grain
      module: fdg
      items:
        - args:
            fdg_file: 'salt://fdg/my_fdg_file.fdg'  # filename for fdg routine
          comparator:
            type: boolean
            match: true
"""
import logging

import hubblestack.module_runner.runner_factory as runner_factory
import hubblestack.module_runner.runner_utils as runner_utils
from hubblestack.exceptions import HubbleCheckValidationError

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
    log.debug('Module: FDG Connector Start validating params for check-id: {0}'.format(block_id))

    error = {}
    # fetch required param
    fdg_file_chained = runner_utils.get_chained_param(extra_args)
    if not fdg_file_chained:
        fdg_file = runner_utils.get_param_for_module(block_id, block_dict, 'fdg_file')
    if not fdg_file_chained and not fdg_file:
        error['fdg_file'] = 'Mandatory parameter: fdg_file not found for id: %s' % (block_id)

    if error:
        raise HubbleCheckValidationError(error)

    log.debug('Validation success for check-id: {0}'.format(block_id))


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
    log.debug('Executing FDG Connector module for id: {0}'.format(block_id))

    fdg_file = runner_utils.get_chained_param(extra_args)
    if not fdg_file:
        fdg_file = runner_utils.get_param_for_module(block_id, block_dict, 'fdg_file')

    # read other params for fdg connector module
    starting_chained = runner_utils.get_param_for_module(block_id, block_dict, 'starting_chained')
    true_for_success = runner_utils.get_param_for_module(block_id, block_dict, 'true_for_success', True)
    use_status = runner_utils.get_param_for_module(block_id, block_dict, 'use_status', False)
    consolidation_operator = runner_utils.get_param_for_module(block_id, block_dict, 'consolidation_operator', 'and')
    try:
        # fdg runner class
        fdg_runner = runner_factory.get_fdg_runner()
        fdg_runner.init_loader()

        # Handover to fdg_runner
        _, fdg_run = fdg_runner.execute(fdg_file, {
            'starting_chained': starting_chained
        })
    except Exception as e:
        raise HubbleCheckValidationError('fdg_runner raised {0}: in file {1}, {2}'.format(e.__class__, fdg_file, e))

    if not isinstance(fdg_run, tuple):
        log.debug("consolidation_operator is %s", consolidation_operator)
        fdg_run = _get_consolidated_result(fdg_run, consolidation_operator)

    fdg_result, fdg_status = fdg_run
    check_value = fdg_status if use_status else bool(fdg_result)

    if true_for_success == check_value:
        return runner_utils.prepare_positive_result_for_module(block_id, True)
    return runner_utils.prepare_negative_result_for_module(block_id, False)


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
    fdg_file = runner_utils.get_chained_param(extra_args)
    if not fdg_file:
        fdg_file = runner_utils.get_param_for_module(block_id, block_dict, 'fdg_file')

    return {'fdg_file': fdg_file}


def _get_consolidated_result(fdg_run, consolidation_operator):
    """
    Consolidate result for FDG
    """
    fdg_run_copy = fdg_run

    while isinstance(fdg_run_copy, list) and isinstance(fdg_run_copy[0], list):
        fdg_run_copy = fdg_run_copy[0]

    if not isinstance(fdg_run_copy, list):
        log.error("something went wrong while consolidating fdg_result, "
                  "unexpected structure of %s found, it is not a list", fdg_run)
        return fdg_run, False

    if not consolidation_operator:
        log.error("invalid value of consolidation operator %s found, returning False", consolidation_operator)
        return fdg_run, False
    if consolidation_operator != "and" and consolidation_operator != "or":
        log.error("operator %s not supported, returning False", consolidation_operator)
        return fdg_run, False

    overall_result = consolidation_operator == 'and'
    for item in fdg_run_copy:
        if not isinstance(item, tuple):
            log.error("something went wrong while consolidating fdg_result, "
                      "unexpected structure of %s found, it is not a tuple", fdg_run)
            return fdg_run, False

        fdg_result, fdg_status = item
        if consolidation_operator == "and":
            overall_result = overall_result and fdg_status
        else:
            overall_result = overall_result or fdg_status
    return fdg_run, overall_result
