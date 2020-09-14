# -*- encoding: utf-8 -*-
"""
String type comparator used to match Strings

String comparator exposes various commands:
- "match" command example:
  
    comparator:
        type: string
        match: '^root'
        is_regex: true # Optional, default False
        exact_match: false # Optional, default True
        case_sensitive: false # Optional, default True

- "match_any" command example:
  
    comparator:
        type: string
        match_any: 
            - '^root'
            - 'shadow'
        is_regex: true # Optional, default False
        exact_match: false # Optional, default True
        case_sensitive: false # Optional, default True

Note: If is_regex=True, then exact_match will be ignored
"""
import logging
import re

from hubblestack.utils.hubble_error import HubbleCheckValidationError

log = logging.getLogger(__name__)

def match(audit_id, result_to_compare, args):
    """
    Match String
    
    :param result_to_compare:
        The value to compare.
    :param args:
        Comparator dictionary as mentioned in the check.
    """
    log.debug('Running string::match for check: {0}'.format(audit_id))

    if _compare(result_to_compare, str(args['match']), args):
        return True, "Check Passed"
    return False, "string::match failure. Expected={0} Got={1}".format(result_to_compare, str(args['match']))

def match_any(audit_id, result_to_compare, args):
    """
    Match list of strings
    
    :param result_to_compare:
        The value to compare.
    :param args:
        Comparator dictionary as mentioned in the check.
    """
    log.debug('Running string::match_any for check: {0}'.format(audit_id))
    
    for option_to_match in args['match_any']:
        if _compare(result_to_compare, option_to_match, args):
            return True, "Check passed"

    # did not match
    return False, "string::match_any failure. Could not find {0} in list: {1}".format(result_to_compare, str(args['match_any']))

def _compare(result_to_compare, expected_string, args):
    """
    Compare two strings, by processing different options
        (case_sensitive, is_regex, exact_match)
    """
    # process case_sensitive option
    is_case_sensitive = args.get('case_sensitive', True)
    if not is_case_sensitive:
        result_to_compare = result_to_compare.lower()
        expected_string = expected_string.lower()

    # process is_regex
    is_regex = args.get('is_regex', False)
    if is_regex:
        return re.search(expected_string, result_to_compare)
    else:
        # process exact_match
        exact_match = args.get('exact_match', True)
        if exact_match:
            return result_to_compare == expected_string
        else:
            return expected_string in result_to_compare
