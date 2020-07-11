"""
HubbleStack FDG module for using stat to verify ownership & permissions.

1. Sample FDG profile, with inline comments:
This profile makes direct use of stat module by passing filepath directly in params
*****************************************************
main:                             # start of this profile's main module
    module: stat.check_stats      # this tells FDG to call stat submodule's check_stats function
    args:                         # arguments to check_stats function
        - filepath: /etc/docker/daemon.json
          mode: 644
          gid: 0
          group: root
          uid: 0
          user: root
          allow_more_strict: True
          match_on_file_missing: True
*****************************************************

2. Sample FDG profile, with inline comments:
This profile chains the stat module, so that some module can pass filepath to stat module.
*****************************************************
main:                           # start of this profile's main module
    module: osquery.query       # this tells FDG to call osquery submodule's query function
    args:
       - 'select path as filepath from FILE where path="/etc/docker/daemon.json";'
    xpipe:                      # This tells FDG to pass the output of the above query to check_stats functions of this profile
       check_stats

check_stats:                    # this profile's check_stats module
    module: stat.check_stats   # this tells FDG to call stat submodule's check_stats function
    args:
        - mode: 644
          gid: 0
          group: root
          uid: 0
          user: root
          allow_more_strict: True
          match_on_file_missing: True

*****************************************************

If `match_on_file_missing` is omitted, success/failure will be determined
entirely based on the other arguments. If it's set to True and
the file is missing, then it will be considered a match (success).
If it's set to False and the file is missing, then it
will be considered a non-match (failure).
If the file exists, this setting is ignored.
"""

import logging
import salt.utils
import salt.utils.platform
import os
log = logging.getLogger(__name__)
import hubblestack.utils.stat_functions as stat_functions


def check_stats(params='', chained=None, chained_status=None):
    """

    :param params: dictionary of parameters to match with the file stats
    :param chained: file path can be passed as chained
    :param chained_status: Status returned by the chained function.
    :return: tuple with (status(Boolean), result(dict))
    This function takes into input stat params that are to be matched with stats of given file.
    The filepath can be provided either directly in params or through chaining. See example above.
    """

    if params == '' or params is None:
        ret = {'Failure' : 'invalid input, no params provided'}
        return False, ret

    if chained:
        log.info("value of 'chained' is not null, using %s value as filepath", chained)
        filepath = chained.get('filepath')
    else:
        filepath = params.get('filepath')

    expected = {}
    for attribute in ['mode', 'user', 'uid', 'group', 'gid', 'allow_more_strict', 'match_on_file_missing']:
        if attribute in params.keys():
            expected[attribute] = params[attribute]

    status, ret = _validate_inputs(filepath, expected)
    if not status:
        log.info("Invalid inputs provided in fdg stat module, returning False")
        return False, ret

    log.info("checking stats of %s", filepath)
    if os.path.exists(filepath):
        salt_ret = __salt__['file.stats'](filepath)
    else:
        salt_ret = {}

    log.debug("file stats are %s", salt_ret)
    if not salt_ret:
        log.info("file stats couldn't be fetched for file %s, checking corner cases", filepath)
        return _check_corner_cases(filepath, expected)

    passed = True
    reason_dict = {}
    for attribute in expected.keys():
        if attribute == 'allow_more_strict' or attribute == 'match_on_file_missing':
            continue
        file_attribute_value = salt_ret[attribute]

        if attribute == 'mode':
            if file_attribute_value != '0':
                file_attribute_value = file_attribute_value[1:]
            allow_more_strict = expected.get('allow_more_strict', False)
            if not isinstance(allow_more_strict, bool):
                passed = False
                reason = "{0} is not a valid boolean. Seems like a bug in hubble profile." \
                    .format(allow_more_strict)
                reason_dict[attribute] = reason

            else:
                subcheck_passed = stat_functions.check_mode(str(expected[attribute]), str(file_attribute_value), allow_more_strict)
                if not subcheck_passed:
                    passed = False
                    reason = {'expected': str(expected[attribute]),
                              'allow_more_strict': str(allow_more_strict),
                              'current': str(file_attribute_value)}
                    reason_dict[attribute] = reason
        else:
            subcheck_passed = (str(expected[attribute]) == str(file_attribute_value))
            if not subcheck_passed:
                passed = False
                reason = {'expected': str(expected[attribute]),
                          'current': str(file_attribute_value)}
                reason_dict[attribute] = reason

    if reason_dict:
        ret = {'Failure': "For file '{0}': {1}".format(filepath, reason_dict), "expected": expected}

    if passed:
        ret = {"Success": "all stats matching for file: {0}".format(filepath), "expected": expected}
        log.info("FDG stat's check_status function is returning status for file %s: True, value : %s", filepath, ret)
        return True, ret
    else:
        log.info("FDG stat's check_status function is returning status : False, value : %s", ret)
        return False, ret


def _check_corner_cases(filepath, expected):
    """
    The function checks if a few corner cases are met or not. The result can be success/failure
    depending upon which case is met.
    :param filepath: File path of file
    :param expected: dictionary of expected params
    :return: Tuple with two value. First is the status, second is the return dictionary with failure reason.
    """
    log.info("checking corner cases for %s", filepath)
    if not expected:
        ret = {"Success" : "nothing is expected, therefore passing the test", "expected": expected}
        log.info("FDG stat's _check_corner_cases function is returning status : True, value : %s", ret)
        return True, ret
    elif 'match_on_file_missing' in expected.keys() and expected['match_on_file_missing']:
        ret = {"Success": "unable to find file, passing check because 'match_on_file_missing' is 'True'", "expected": expected}
        log.info("FDG stat's _check_corner_cases function is returning status : True, value : %s", ret)
        return True, ret
    else:
        reason = "Could not get access any file at '{0}'. " \
                 "File might not exist, or hubble might not" \
                 " have enough permissions".format(filepath)
        ret = {'Failure': reason, "expected": expected}
        log.info("FDG stat's _check_corner_cases function is returning status : False, value : %s", ret)
        return False, ret


def _validate_inputs(filepath, expected):
    """
    The functions will validate if filepath is specified and mode is provided in the expected params
    :param filepath: File path of file
    :param expected: dictionary of expected params
    :return: Tuple with two value. First is the status, second is the return dictionary with failure reason.
    """
    ret = ''
    log.info("validating inputs for %s in fdg stat module", filepath)
    if not filepath:
        log.error("filepath not specified to FDG stat module")
        ret = {'Failure': "no filepath provided", "expected": expected}
        log.info("FDG stat's _validate_inputs function is returning status : False, value : %s", ret)
        return False, ret

    if 'allow_more_strict' in expected and 'mode' not in expected:
        reason = "'allow_more_strict' tag can't be specified without 'mode' tag." \
                 " Seems like a bug in hubble profile."
        ret = {'Failure': reason, "expected": expected}
        log.info("FDG stat's _validate_inputs function is returning status : False, value : %s", ret)
        return False, ret

    return True, ret
