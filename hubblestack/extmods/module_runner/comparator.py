# -*- encoding: utf-8 -*-
"""
An Orchestrator for Comparators
This is used by Audit runners to initiate comparisons
Also, if a specific comparator is mentioned in other comparator. This will be invoked.
"""

import logging
from hubblestack.utils.hubble_error import HubbleCheckFailedError

log = logging.getLogger(__name__)


def run(audit_id, args, module_result, module_status=True):
    """
    Start the comparator execution
    """

    # First check if module failed, and is failed with whitelisted errors
    if 'success_on_error' in args and not module_status:
        if module_result['error'] in args['success_on_error']:
            success_msg = 'success_on_error is on and module failed with the configured error. Passing this check {0}'.format(
                audit_id)
            return True, success_msg
        error_msg = 'success_on_error is on, but the check: {0} is failed with error: {1}. \
            Not proceeding with comparator'.format(audit_id, module_result['error'])
        log.error(error_msg)
        return False, error_msg
    elif not module_status:
        # Not invoking comparator for fail result of a module
        error_msg = 'Module status is False, not invoking comparator. Output={0}'.format(str(module_result))
        log.error(error_msg)
        return False, error_msg

    global __comparator__

    comparator_command_method_name = _find_comparator_command(args)
    if not comparator_command_method_name:
        # raise error when no matched command found
        raise HubbleCheckFailedError('Unknown comparator or command for: {0}'.format(args['type']))

    if isinstance(module_result, int) or isinstance(module_result, float):
        result_val = module_result
    else:
        result_val = module_result['result'] if 'result' in module_result else module_result
    comparator_result = __comparator__[comparator_command_method_name](audit_id, result_val, args)

    return comparator_result


def _find_comparator_command(args):
    """
    Find matched comparator's command
    """
    for comparator_key in args.keys():
        if comparator_key in ['type', 'success_on_error']:
            continue

        method_name = '{0}.{1}'.format(args['type'], comparator_key)
        if method_name in __comparator__:
            return method_name
    return None
