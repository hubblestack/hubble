# -*- encoding: utf-8 -*-
"""
Version type comparator used to match versions

Version comparator exposes various commands:
- "match" command example:
  
    comparator:
        type: version
        match: >= 3.28.0-1.el7
        # < <= > >= !=

    comparator:
        type: version
        match: 3.28.0-1.el7
        # < <= > >= !=

- "match_any" command example:
  
    comparator:
        type: version
        match_any:
            - 3.28.0-1.el7
            - >= 4.28.0-1.el7
            - < 5.28.0-1.el7

Complete Example

    comparator:
        type: "dict"
        match:
            name: rsync
            version:
                type: version
                match: 3.28.0-1.el7

    comparator:
        type: "dict"
        match:
            rsync:
                type: version
                match: 3.28.0-1.el7
"""

import logging
from distutils.version import LooseVersion

log = logging.getLogger(__name__)


def match(audit_id, result_to_compare, args):
    """
    Match Version

    :param result_to_compare:
        Version string values to compare
    :param args:
        Comparator dictionary as mentioned in the check.
    """
    log.debug('Running version::match for audit_id: {0}'.format(audit_id))

    if _match(result_to_compare, args['match']):
        return True, "Check Passed"
    return False, "version::match failure. Got={0} Expected={1}".format(result_to_compare, str(args['match']))


def match_any(audit_id, result_to_compare, args):
    """
    Match against list of versions
        
    :param result_to_compare:
        The value to compare.
    :param args:
        Comparator dictionary as mentioned in the check.
    """
    log.debug('Running version::match_any for check: {0}'.format(audit_id))

    for option_to_match in args['match_any']:
        if _match(result_to_compare, option_to_match):
            return True, "Check passed"

    # did not match
    return False, "version::match_any failure. Could not find {0} in list: {1}".format(result_to_compare,
                                                                                       str(args['match_any']))


def _match(result_to_compare, expected_result):
    """
    compare versions
    """
    # got string having some comparison operators
    expected_result_value = expected_result.strip()
    result_version_to_compare = LooseVersion(result_to_compare)

    if expected_result_value.startswith('<='):
        return result_version_to_compare <= LooseVersion(expected_result_value[2:].strip())
    elif expected_result_value.startswith('>='):
        return result_version_to_compare >= LooseVersion(expected_result_value[2:].strip())
    elif expected_result_value.startswith('<'):
        return result_version_to_compare < LooseVersion(expected_result_value[1:].strip())
    elif expected_result_value.startswith('>'):
        return result_version_to_compare > LooseVersion(expected_result_value[1:].strip())
    elif expected_result_value.startswith('=='):
        return result_version_to_compare == LooseVersion(expected_result_value[2:].strip())
    elif expected_result_value.startswith('!='):
        return result_version_to_compare != LooseVersion(expected_result_value[2:].strip())
    else:
        # direct comparison
        return result_version_to_compare == LooseVersion(expected_result_value.strip())
