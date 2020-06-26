# -*- encoding: utf-8 -*-
"""
Nova module to check whether a package is installed on host machine

Example yaml for check:
check_unique_id:
  description: 'sample description'
  tag: 'ADOBE-00041'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      module: pkg
      checks:
        - name: rsync
          # Optional param: version
          version: "3.1.2-10.el7"

Here we are checking if "rsync" package is installed or not. We can have more than one package listed here

Version Comparison:
Optional param: "version" is to check the version of installed package
Following operators are allowed in version comparison:
>=, <=, >, <

If version is given with no operator, Default is exact comparison.

Regex Support
We have support for '*'. Example: name: rpm*

Note: In this case it might return multiple packages, and if you have given version comparison too.
All matched packages must comply to that version string.

You can give multiple packages in the yaml, under "checks" attribute.
"""
import logging
import os
import re

from packaging import version

from hubblestack.utils.hubble_error import AuditCheckValidationError
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

    log.debug("Checking for package installed or not: %s" %(audit_check['name']))

    # fetch package info from system
    pkg_found = __salt__['pkg.version'](audit_check['name'])
    if not pkg_found:
        return {"result": False, 
            "failure_reason": "Could not find requisite package '{0}' installed" \
                                                         " on the system".format(audit_check['name'])}
    
    # package found, check if we have to do version comparison
    errors = {}

    # if multiple packages came as a result, we would want to iterate over it.
    # For single result, it just returns version.
    # Converting string result into dict
    if isinstance(pkg_found, str):
        tmp_dict = {}
        tmp_dict[audit_check['name']] = pkg_found
        pkg_found = tmp_dict

    if 'version' in audit_check:
        pkg_version = audit_check['version'].replace(' ', '')
        for package in pkg_found:
            if not _match_version(pkg_version, pkg_found[package]):
                errors[package] = "Package: %s, version found: %s, Expected: %s" %(package, pkg_found[package], pkg_version)

    if errors:
        # error string will have version along with operator if passed from profile
        print("Package version mismatch: %s" %(str(errors)))
        return {"result": False, "failure_reason": "Package version mismatch: %s" %(str(errors))}

    return {"result": True}

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
        'name': audit_check['name']
    }

def validate_params(check_id, audit_check):
    """Validate all mandatory params required for this module

    Arguments:
        check_id {str} -- Audit check id
        audit_check {dict} -- Single audit check for this module

    Raises:
        AuditCheckValidationError: For any validation error
    """
    log.info('Module: pkg Start validating params for check-id: %s' %(check_id))

    if 'name' not in audit_check:
        raise AuditCheckValidationError('Mandatory parameter name is not present in check_id: %s' %(check_id))

    log.debug('Validatiion success for check-id: %s' %(check_id))

def _match_version(pkg_version_to_match, pkg_version_found):
    """
    pkg_version_to_match can have string like ">=4.0.1, <4.9.0"
    compare version accordingly
    """
    if pkg_version_to_match.startswith('<='):
        version_comparison_result = version.parse(pkg_version_found) <= version.parse(pkg_version_to_match[2:])
    elif pkg_version_to_match.startswith('>='):
        version_comparison_result = version.parse(pkg_version_found) >= version.parse(pkg_version_to_match[2:])
    elif pkg_version_to_match.startswith('<'):
        version_comparison_result = version.parse(pkg_version_found) < version.parse(pkg_version_to_match[1:])
    elif pkg_version_to_match.startswith('>'):
        version_comparison_result = version.parse(pkg_version_found) > version.parse(pkg_version_to_match[1:])
    else:
        # check for exact version
        version_comparison_result = version.parse(pkg_version_found) == version.parse(pkg_version_to_match)
    
    return version_comparison_result
