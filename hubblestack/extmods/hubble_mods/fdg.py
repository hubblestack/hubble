# -*- encoding: utf-8 -*-
"""
FDG Connector module for writing audit profiles with FDG.
Since chaining is only present in FDG, Audit modules can use this module to invoke a FDG profile.

This audit module requires yaml data to execute. It will search the local
directory for any .yaml files, and if it finds a top-level 'fdg' key, it will
use that data.

Sample YAML data, with inline comments:

fdg_check:   # unique ID
  description: 'sample description'
  tag: 'ADOBE-00041'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7' # osfinger grain
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

The ``true_for_success`` argument decides how success/failure are decided
based on the fdg return. By default, any "truthy" value in the ``results`` piece
of the FDG return will constitute success. Set this option to False to treat
"falsey" values as success.

The ``use_status`` argument determines whether the status result or the actual
result returned from fdg will be used. If this is True, only the status result of
the fdg run will be considered. If it is False, only the actual result of the
fdg run will be considered. Regardless, the ``true_for_success`` argument
will be respected.

The consolidation_operator is used when chaining is done using xpipe and the
returned result is a list. If the list contains more than one tuple, the
result is consolidated based on the consolidation operator.
"""
import logging

import hubblestack.extmods.module_runner.runner_factory as runner_factory
import hubblestack.extmods.module_runner.runner_utils as runner_utils
from hubblestack.utils.hubble_error import HubbleCheckValidationError

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

    # fdg runner class
    fdg_runner = runner_factory.get_fdg_runner()
    fdg_runner.init_loader()

    # Handover to fdg_runner
    _, fdg_run = fdg_runner.execute(fdg_file, {
        'starting_chained': starting_chained
    })

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
