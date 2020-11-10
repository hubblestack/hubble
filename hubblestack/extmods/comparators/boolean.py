# -*- encoding: utf-8 -*-
"""
Boolean type comparator used to match Boolean

Comparators are used by Audit module to compare module output 
with the expected result
In FDG-connector, comparators might also be used with FDG

Boolean comparator exposes various commands:
- "match" 
    Use Cases:
        - To check a boolean value against boolean true/false
        - To check whether we got anything (boolean_typecast)
          i.e. True for anything, False for None or empty string
    
    example:
    
    comparator:
        type: boolean
        match: True
        boolean_cast: False # Optional param
"""
import logging

log = logging.getLogger(__name__)


def match(audit_id, result_to_compare, args):
    """
    Match against a boolean
        match: True
    
    :param result_to_compare:
        The value to compare.
    :param args:
        Comparator boolean as mentioned in the check.
    """
    log.debug('Running boolean::match for check: {0}'.format(audit_id))

    # if result_to_compare is not of boolean type, but we want a type-cast
    boolean_cast = args.get('boolean_cast', False)

    value_to_compare = result_to_compare
    if boolean_cast:
        value_to_compare = bool(value_to_compare)

    if value_to_compare == args['match']:
        return True, "Check Passed"
    return False, "boolean::match failure. Expected={0} Got={1}".format(str(args['match']), result_to_compare)
