# -*- encoding: utf-8 -*-
"""
Number type comparator used to match numbers

Number comparator exposes various commands:
- "match" command example:
  
    comparator:
        type: number
        match: >= 10
        # < <= > >= !=

- "match_any" command example:
  
    comparator:
        type: number
        match_any:
            - 10
            - > 20
            - != 100
        # < <= > >= !=

Complete Example

    comparator:
        type: "dict"
        match:
            gid:
                type: number
                match_any:
                    - 0
                    - 1
                    - 2
            uid: 0 
            user: root
"""

import logging

from hubblestack.utils.hubble_error import HubbleCheckValidationError

log = logging.getLogger(__name__)


def match(audit_id, result_to_compare, args):
    """
    Match a number
        match: 10
        match: "> 10"
    
    :param audit_id:
    :param result_to_compare:
        The value to compare.
    :param args:
        Comparator dictionary as mentioned in the check.
    """
    log.debug('Running number::match for check: {0}'.format(audit_id))

    if _match(result_to_compare, args['match']):
        return True, "Check Passed"
    return False, "number::match failure. Expected={0} Got={1}".format(result_to_compare, str(args['match']))


def match_any(audit_id, result_to_compare, args):
    """
    Match against list of numbers
        match_any:
            - 10
            - > 20
            - != 100
    
    :param audit_id:
    :param result_to_compare:
        The value to compare.
    :param args:
        Comparator dictionary as mentioned in the check.
    """
    log.debug('Running string::match_any for check: {0}'.format(audit_id))

    for option_to_match in args['match_any']:
        if _match(result_to_compare, option_to_match):
            return True, "Check passed"

    # did not match
    return False, "number::match_any failure. Could not find {0} in list: {1}".format(result_to_compare,
                                                                                      str(args['match_any']))


def _match(result_to_compare, expected_result):
    """
    compare a number
    """
    if isinstance(expected_result, int):
        return result_to_compare == expected_result

    # got string having some comparison operators
    expected_result_value = expected_result.strip()
    if expected_result_value.startswith('<='):
        return result_to_compare <= int(expected_result_value[2:].strip())
    elif expected_result_value.startswith('>='):
        return result_to_compare >= int(expected_result_value[2:].strip())
    elif expected_result_value.startswith('<'):
        return result_to_compare < int(expected_result_value[1:].strip())
    elif expected_result_value.startswith('>'):
        return result_to_compare > int(expected_result_value[1:].strip())
    elif expected_result_value.startswith('=='):
        return result_to_compare == int(expected_result_value[2:].strip())
    elif expected_result_value.startswith('!='):
        return result_to_compare != int(expected_result_value[2:].strip())
    else:
        raise HubbleCheckValidationError('Unknown operator in number::match arg: {0}'
                                         .format(expected_result_value))
