# -*- encoding: utf-8 -*-
"""
Dictionary type comparator used to match a dictionary input with expected output

Comparators are used by Audit module to compare module output
with the expected result
In FDG-connector, comparators might also be used with FDG

Dictionary comparator exposes various commands:

- "match"
    To match module output against a dictionary
    (dictionary can be nested to any level)

    comparator:
        type: "dict"
        match:
            gid: 0
            uid: 0
            attr2:
                key1: val1

- "match_key_any"
    True for any key found from the list

    comparator:
        type: "dict"
        match_key_any:
            - /sys
            - /abc

- "match_key_all"
    True when all keys found from the list

    comparator:
        type: "dict"
        match_key_all:
            - /sys
            - /abc

- "match_any"
    True when any dictionary mentioned in list match

    comparator:
        type: "dict"
        match_any:
            - name: abc
              running: false
            - name: xyz
              running: true

- "match_any_if_keyvalue_matches"
  This is a special case when user want to match only when desired key-value is found.
  Example: If name=rsync found, then match other attributes.

  Result will be True
    - if specified key not found.
    - key-value found and attributes also matched
  Result will be False
    - Key-value found and attributes did not match

    comparator:
        type: "dict"
        match_any_if_keyvalue_matches:
            match_key: name
            args:
                - name: abc
                  running: false
                - name: xyz
                  running: true

    Examples:
        1.  output from a module: 
                {name: 'splunkd', running: false, enabled: true}
            match_any_if_keyvalue_matches:
                match_key: name
                args:
                    - name: abc
                      running: false
                    - name: def
                      running: true
            Result: True
            Reason: Since result does not have "name" as either [abc, def]
                    And, we want to match only when we found our desired key-value
        2.  output from a module: 
                {name: 'splunkd', running: false, enabled: true}
            match_any_if_keyvalue_matches:
                match_key: name
                args:
                    - name: abc
                      running: false
                    - name: splunkd
                      running: false
            Result: True
            Reason: Since result matches "name: splunkd" and "running: false"
                    
        3.  output from a module: 
                {name: 'splunkd', running: false, enabled: true}
            match_any_if_keyvalue_matches:
                match_key: name
                args:
                    - name: abc
                      running: false
                    - name: splunkd
                      running: true
            Result: False
            Reason: Since result matches "name: splunkd", but did not match "running" attribute
        

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

Complete Example with a Module

check_id:
  description: 'sample description'
  tag: 'ADOBE-00041'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      module: stat
      items:
        - args:
            path: /etc/ssh/ssh_config
          comparator:
            type: "dict"
            success_on_error:
              - "file_not_found"
            match:
              gid: 0
              uid: 0
              group: root
              user: root
              mode:
                type: file_permission
                match:
                  required_value: 644
                  allow_more_strict: true
"""

import logging

import hubblestack.module_runner.comparator

log = logging.getLogger(__name__)


def _compare_dictionary_values(audit_id, result_to_compare, args, errors):
    for key, value in result_to_compare.items():
        if isinstance(value, dict):
            _compare_dictionary_values(audit_id, value, args, errors)
        else:
            if 'type' in args:
                ret_status, ret_val = hubblestack.module_runner.comparator.run(audit_id, args, int(value))
                if not ret_status:
                    errors.append(ret_val)


def compare_all_values(audit_id, result_to_compare, args):
    """
    For a given dictionary, this function will only consider the values.
    All values must match.
    Example :
    {
    'HKEY_USERS\\<SID>\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop\\ScreenSaveTimeOut':
        {
        'S-1-5-21-1645406227-2048958880-3100449314-500': '900',
        'S-1-5-21-1645406227-2048958880-3100449314-1008': 900
        }
    }
    for the above dictionary, you can use this function to compare the leaf values to be 900.
    :param audit_id
        audit_id for the check
    :param result_to_compare:
        Dictionary values to compare
    :param args:
        Comparator dictionary as mentioned in the check.
    """
    errors = []
    _compare_dictionary_values(audit_id, result_to_compare, args['compare_all_values'], errors)
    if errors:
        error_message = 'dict::match failed, errors={0}'.format(str(errors))
        log.debug("for check %s errors occurred %s", audit_id, error_message)
        return False, error_message
    return True, "Dictionary comparison passed"


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


def match_any(audit_id, result_to_compare, args):
    """
    Match dictionary elements dynamically.
    Match from a list of available dictionaries
    True for any match found

    :param result_to_compare:
        Dictionary values to compare
    :param args:
        Comparator dictionary as mentioned in the check.
    """
    log.debug('Running dict::match_any for audit_id: {0}'.format(audit_id))

    for to_match_dict in args['match_any']:
        errors = []
        _compare_dictionary(audit_id, result_to_compare, to_match_dict, errors)
        if not errors:
            # found a match
            return True, "Dictionary comparison passed"

    error_message = 'dict::match_any failed, errors={0}'.format(str(errors))
    return False, error_message


def match_any_if_keyvalue_matches(audit_id, result_to_compare, args):
    """
    We want to compare things if we found our interested key-value
    Even if the list does not have my interested name, it will pass

    Match dictionary elements dynamically. Match from a list of available dictionaries
    There is an argument: match_key. Match only when we found this key in result_to_compare

    True, if match_key found, and mentioned attributes matches
        , if match_key NOT found. Not even try to match anything else
    False, if match_key found and attributes do not match

    comparator:
        type: dict
        match_any_if_keyvalue_matches:
            match_key: name
            args:
                - name: abc
                  running: false
                - name: xyz
                  running: false

    Input: {name: hjk, running: false}
    Output: True, as didn't found name: hjk

    Input: {name: abc, running: false}
    Output: True, as found name: abc and matched running: false

    :param result_to_compare:
        Dictionary values to compare
    :param args:
        Comparator dictionary as mentioned in the check.
    """
    log.debug('Running dict::match_any_if_keyvalue_matches for audit_id: {0}'.format(audit_id))

    key_name = args['match_any_if_keyvalue_matches']['match_key']
    if key_name not in result_to_compare:
        log.debug("Required key '%s' is not found in '%s' for audit_id '%s'", key_name, result_to_compare, audit_id)
        return True, "pass_as_keyvalue_not_found"

    key_found_once = False
    for to_match_dict in args['match_any_if_keyvalue_matches']['args']:
        errors = []
        if result_to_compare[key_name] == to_match_dict[key_name]:
            key_found_once = True
            _compare_dictionary(audit_id, result_to_compare, to_match_dict, errors)

            if not errors:
                # found a match
                return True, "Dictionary comparison passed"

    if key_found_once:
        error_message = 'dict::match_any_if_keyvalue_matches failed, errors={0}'.format(str(errors))
        return False, error_message
    return True, "pass_as_keyvalue_not_found"


def match_key_any(audit_id, result_to_compare, args):
    """
    Match dictionary elements dynamically. True for any key found from a list of keys

    :param result_to_compare:
        Dictionary values to compare
    :param args:
        Comparator dictionary as mentioned in the check.
    """
    log.debug('Running dict::match_key_any for audit_id: {0}'.format(audit_id))

    for key_to_match in args['match_key_any']:
        if key_to_match in result_to_compare:
            return True, 'dict::match_key_any passed for key: {0}'.format(key_to_match)

    return False, 'dict::match_key_any failed'


def match_key_all(audit_id, result_to_compare, args):
    """
    Match dictionary elements dynamically. True when all keys found in the result

    :param result_to_compare:
        Dictionary values to compare
    :param args:
        Comparator dictionary as mentioned in the check.
    """
    log.debug('Running dict::match_key_all for audit_id: {0}'.format(audit_id))

    errors = []
    for key_to_match in args['match_key_all']:
        if key_to_match not in result_to_compare:
            errors.append('key={0} not found'.format(key_to_match))

    if errors:
        error_message = 'dict::match_key_all failed, errors={0}'.format(str(errors))
        return False, error_message
    return True, "dict::match_key_all passed"


def _compare_dictionary(audit_id, input_dictionary, expected_dictionary, errors):
    for key, value in expected_dictionary.items():
        if key not in input_dictionary:
            errors.append('Key: {0} not found in result'.format(key))
            continue

        if isinstance(value, dict):
            if 'type' in value:
                # Lets hand-over this new specific comparison to comparator orchestrator
                ret_status, ret_val = hubblestack.module_runner.comparator.run(
                    audit_id, value, input_dictionary[key])
                if not ret_status:
                    errors.append(ret_val)
            else:
                # got nested dictionary to compare
                _compare_dictionary(audit_id, input_dictionary[key], expected_dictionary[key], errors)

        else:
            if input_dictionary[key] != value:
                errors.append('Expected={0}, Got={1}'.format(input_dictionary[key], value))
