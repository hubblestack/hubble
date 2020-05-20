# -*- encoding: utf-8 -*-

import logging
import os
import re

from hubblestack.utils.hubble_error import AuditCheckValdiationError
from hubblestack.utils.hubble_error import AuditCheckFailedError
from salt.exceptions import CommandExecutionError

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

    # check file presence
    if not os.path.isfile(audit_check['path']):
        if 'success_on_file_missing' in audit_check and audit_check['success_on_file_missing']:
            return {"result": True, "output": "File not present and success_on_file_missing flag is true"}
        else:
            return {"result": False, "failure_reason": "File not present"}

    # get stats
    stat_res = __salt__['file.stats'](audit_check['path'])

    error = {}

    # compare result
    if stat_res['gid'] != audit_check['gid']:
        error['gid'] = 'Expected: %s, got: %s' %(audit_check['gid'], stat_res['gid'])
    if stat_res['group'] != audit_check['group']:
        error['group'] = 'Expected: %s, got: %s' %(audit_check['group'], stat_res['group'])
    if stat_res['user'] != audit_check['user']:
        error['user'] = 'Expected: %s, got: %s' %(audit_check['user'], stat_res['user'])
    if stat_res['uid'] != audit_check['uid']:
        error['uid'] = 'Expected: %s, got: %s' %(audit_check['uid'], stat_res['uid'])
    
    # For mode check, complexity added by param: allow_more_strict
    allow_more_strict = 'allow_more_strict' in audit_check and audit_check['allow_more_strict']
    mode_result = _check_mode(str(audit_check['mode']), str(stat_res['mode'][1:]), allow_more_strict)
    if not mode_result:
        error['mode'] = 'Expected: %s, got: %s' %(audit_check['mode'], stat_res['mode'])

    if error:
        return {"result": False, "failure_reason": error}

    return {"result": True}

def get_filtered_params_to_log(check_id, audit_check):
    """For getting params to log, in non-verbose logging

    Arguments:
        check_id {str} -- Audit check id
        audit_check {dict} -- Single audit check for this module

    Returns:
        dict -- Dictionary of params to log
    """
    log.info('Getting filtered parameters to log for check-id: %s' %(check_id))
    return {
        "path": audit_check['path'],
        "gid": audit_check['gid'],
        "uid": audit_check['uid']
    }

def validate_params(check_id, audit_check):
    """Validate all mandatory params required for this module

    Arguments:
        check_id {str} -- Audit check id
        audit_check {dict} -- Single audit check for this module

    Raises:
        AuditCheckValdiationError: For any validation error
    """
    log.info('Start validating for check-id: %s' %(check_id))

    mandatory_params = ['path', 'gid', 'group', 'mode', 'uid', 'user']
    error = {}
    for mandatory_param in mandatory_params:
        if mandatory_param not in audit_check:
            # collect all errors
            error[mandatory_param] = 'Mandatory parameter: %s not found' %(check_id, mandatory_param)
    
    if error:
        raise AuditCheckValdiationError(error)

    log.debug('Validatiion success for check-id: %s' %(check_id))


def _check_mode(max_permission, given_permission, allow_more_strict):
    """
    Checks whether a file's permission are equal to a given permission or more restrictive.
    Permission is a string of 3 digits [0-7]. 'given_permission' is the actual permission on file,
    'max_permission' is the expected permission on this file. Set 'allow_more_strict' to True,
    to allow more restrictive permissions as well. Example:

    _check_mode('644', '644', False)        returns         True
    _check_mode('644', '600', False)        returns         False
    _check_mode('644', '644', True)         returns         True
    _check_mode('644', '600', True)         returns         True
    _check_mode('644', '655', True)        returns         False

    """

    if given_permission == '0':
        return True

    if ((not allow_more_strict) or (max_permission == 'None')):
        return (max_permission == given_permission)

    if (_is_permission_in_limit(max_permission[0], given_permission[0]) and _is_permission_in_limit(max_permission[1], given_permission[1]) and _is_permission_in_limit(max_permission[2], given_permission[2])):
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