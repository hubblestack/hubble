# -*- encoding: utf-8 -*-
"""
Dictionary type comparator used to match a dictionary input with expected output

Dictionary comparator exposes various commands:
- "match" command example: (dictionary can be nested to any level)
  
    comparator:
        type: "dict"
        match:
            gid: 0
            uid: 0 
            user: root

If we need other specific comparison with any field, we specify it like below:
    comparator:
        type: "dict"
        match: 
            gid: 0
            uid: 0
            mode:
                type: file_permission
                match:
                    required_value: 644
                    allow_more_strict: true
In above example, we are invoking another comparator: "file_permission" for "mode" field.

Example with nested dictionary
---------------------------------
    comparator:
        type: "dict"
        match: 
            key1:
                nkey1: nkey2
                key:
                    key1: val1
                    key2: val2
                mode:
                    type: file_permission
                    match:
                        required_value: 644
                        allow_more_strict: true
            keyn: valn
            vals:
                type: string
                match_any:
                    - val1
                    - val2
"""

import logging

import hubblestack.extmods.module_runner.comparator
from hubblestack.utils.hubble_error import HubbleCheckValidationError

log = logging.getLogger(__name__)

def match(audit_id, result_to_compare, args):
    """
    Match dictionary elements dynamically. All elements must match

    :param result_to_compare:
        Dictionary values to compare
    :param args:
        Comparator dictionary as mentioned in the check.
    """
    log.debug('Running dict::match for audit_id: {0}'.format(audit_id))
    
    errors = []
    _compare_dictionary(audit_id, result_to_compare, args['match'], errors)
    
    if errors:
        error_message = 'dict::match failed, errors={0}'.format(str(errors))
        return False, error_message
    return True, "Dictionary comparison passed"

def _compare_dictionary(audit_id, input_dictionary, expected_dictionary, errors):
    for key, value in expected_dictionary.items():
        if key not in input_dictionary:
            errors.append('Key: {0} not found in result'.format(key))
            continue

        if isinstance(value, dict):
            if 'type' in value:
                # Lets hand-over this new specific comparison to comparator orchestrator
                ret_status, ret_val = hubblestack.extmods.module_runner.comparator.run(
                    audit_id, value, input_dictionary[key])
                if not ret_status:
                    errors.append(ret_val)
            else:
                # got nested dictionary to compare
                _compare_dictionary(audit_id, input_dictionary[key], expected_dictionary[key], errors)
                
        else:
            if input_dictionary[key] != value:
                errors.append('Expected={0}, Got={1}'.format(input_dictionary[key], value))
