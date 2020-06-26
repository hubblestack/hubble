"""
Nova module to check kernel parameters

Example yaml of check
check_unique_id:
  description: 'sample description'
  tag: 'ADOBE-00041'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
    module: pkg
    checks:
        - name: net.ipv4.tcp_syncookies
          match_output: 'sample*'
          match_output_regex: true

Here we are checking value of kernel param 'net.ipv4.tcp_syncookies' and matching it with the regex 'sample*'
Param match_output_regex is optional and it's default value is False

Regex support:
If match_output_regex is set to true, then match_output is treated as regex pattern and the output of sysctl command is matched with that pattern

If  match_regex_support is False, then exact string matching is done for the result and match_output command
Multiple commands can be passed in checks with their outputs.
"""
import logging
import re

from hubblestack.utils.hubble_error import AuditCheckValidationError

log = logging.getLogger(__name__)

def execute(check_id, audit_check):
    """Execute single check

        Arguments:
            check_id {str} -- Unique check id
            audit_check {str} -- Dictionary of an individual check implementation

        Returns:
            dict -- dictionary of result status and output
        """
    log.debug('Executing fdg module for check-id: %s' % (check_id))
    name = audit_check['name']
    match_output = audit_check['match_output']
    match_output_regex = audit_check.get('match_output_regex', False)

    salt_ret = __salt__['sysctl.get'](name)
    if not salt_ret or "No such file or directory" in salt_ret:
        return {"result": False,
                "failure_reason": "Could not find attribute %s in the kernel" %(name)}
    if salt_ret.lower().startswith("ERROR".lower()):
        return {"result": False,
                "failure_reason": "An error occurred while reading the value of kernel attribute %s" %(name)}
    if match_output_regex:
        if not re.search(match_output, salt_ret):
            return {"result": False,
                    "failure_reason": "Current value of kernel attribute %s is %s It is not matching with regex: %s" %(name, salt_ret, match_output)}
    else:
        if str(salt_ret) != str(match_output):
            return {"result": False,
                    "failure_reason": "Current value of kernel attribute %s is %s It should be set to %s" %(name, salt_ret, match_output)}

    return {"result": True}

def get_filtered_params_to_log(check_id, audit_check):
    """For getting params to log, in non-verbose logging

    Arguments:
        check_id {str} -- Audit check id
        audit_check {dict} -- Single audit check for this module

    Returns:
        dict -- Dictionary of params to log
    """
    log.debug('Getting filtered parameters to log for check-id: %s' % (check_id))
    return {
        'name': audit_check['name']
    }


def validate_params(check_id, audit_check):
    """Validate all mandatory params required for this module

        Arguments:
            check_id {str} -- Audit check id
            audit_check {dict} -- Single audit check for this module

        Raises:
            AuditCheckValdiationError: For any validation error
        """
    log.debug('Module: fdg Start validating params for check-id: %s' % (check_id))

    mandatory_params = ['name', 'match_output']
    error = {}
    for mandatory_param in mandatory_params:
        if mandatory_param not in audit_check:
            error[mandatory_param] = 'Mandatory parameter: "%s" not found for check-id: %s' % (mandatory_param, check_id)

    if error:
        raise AuditCheckValidationError(error)

    log.debug('Validatiion success for check-id: %s' %(check_id))