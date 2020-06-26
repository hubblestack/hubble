# -*- encoding: utf-8 -*-

import logging

from hubblestack.utils.hubble_error import AuditCheckValidationError

log = logging.getLogger(__name__)

def execute(check_id, audit_check):
    """Execute single check

    Arguments:
        check_id {str} -- Unique check id
        audit_check {str} -- Dictionary of an individual check implementation

    Returns:
        dict -- dictionary of result status and output

    Raises:
        AuditCheckFailedError -- In case of error
    """
    log.debug('Executing fdg module for check-id: %s' %(check_id))

    fdg_file = audit_check['file']
    
    # starting_chained, an attribute for fdg module. Passing it as it is (if found)
    starting_chained = audit_check.get('starting_chained')
    use_status = audit_check.get('use_status', False)

    _, fdg_run = __salt__['fdg.fdg'](fdg_file, starting_chained=starting_chained)
    fdg_result, fdg_status = fdg_run

    check_value = False
    if use_status:
        check_value = fdg_status
    else:
        check_value = fdg_result

    return {"result": check_value}

def get_filtered_params_to_log(check_id, audit_check):
    """For getting params to log, in non-verbose logging

    Arguments:
        check_id {str} -- Audit check id
        audit_check {dict} -- Single audit check for this module

    Returns:
        dict -- Dictionary of params to log
    """
    log.debug('Getting filtered parameters to log for check-id: %s' %(check_id))
    return {
        'file': audit_check['file']
    }

def validate_params(check_id, audit_check):
    """Validate all mandatory params required for this module

    Arguments:
        check_id {str} -- Audit check id
        audit_check {dict} -- Single audit check for this module

    Raises:
        AuditCheckValidationError: For any validation error
    """
    log.debug('Module: fdg Start validating params for check-id: %s' %(check_id))

    error = {}

    if 'file' not in audit_check:
        error['file'] = 'Mandatory parameter: file param not found for check-id: %s' %(check_id)

    if error:
        raise AuditCheckValidationError(str(error))

    log.debug('Validatiion success for check-id: %s' %(check_id))
