'''
HubbleStack FDG module for using stat to verify ownership & permissions.

1. Sample FDG profile, with inline comments:
This profile makes direct use of stat module by passing filepath directly in params
*****************************************************
main:                             # start of this profile's main module
    module: stat.check_stats      # this tells FDG to call stat submodule's check_stats function
    args:                         # arguments to check_stats function
        - params:
            filepath: /etc/docker/daemon.json
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
        - params:
            mode: 644
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
'''

import logging
import salt.utils
import salt.utils.platform
import os
log = logging.getLogger(__name__)


def check_stats(params='', chained=None, chained_status=None):
    '''

    :param params:
    :param chained:
    :param chained_status:
    :return: tuple with (status(Boolean), result(dict))
    This function takes into input stat params that are to be matched with stats of given file.
    The filepath can be provided either directly in params or through chaining. See example above.
    '''
    params = params.get('params')

    if chained != None:
        log.info("value of 'chained' is not null, using {0} value as filepath".format(chained))
        filepath = chained.get('filepath')
    else:
        filepath = params.get('filepath')

    expected = {}
    for attribute in ['mode', 'user', 'uid', 'group', 'gid', 'allow_more_strict', 'match_on_file_missing']:
        if attribute in params.keys():
            expected[attribute] = params[attribute]

    status, ret = _validate_inputs(filepath, expected)
    if not status:
        log.info("Invalid inputs, returning False")
        return False, ret

    log.info("checking stats of {0}".format(filepath))
    if os.path.exists(filepath):
        salt_ret = __salt__['file.stats'](filepath)
    else:
        salt_ret = {}

    log.debug("file stats are {0}".format(salt_ret))
    if not salt_ret:
        log.info("file stats couldn't be fetched, checking corner cases")
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
            allow_more_strict = False
            if 'allow_more_strict' in expected.keys():
                allow_more_strict = expected['allow_more_strict']
            if not isinstance(allow_more_strict, bool):
                passed = False
                reason = "{0} is not a valid boolean. Seems like a bug in hubble profile." \
                    .format(allow_more_strict)
                reason_dict[attribute] = reason

            else:
                subcheck_passed = _check_mode(str(expected[attribute]), str(file_attribute_value), allow_more_strict)
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
        ret = {'Success': 'all stats matching', "expected": expected}
        log.info("FDG stat is returning status : True, value : {0}".format(ret))
        return True, ret
    else:
        log.info("FDG stat is returning status : False, value : {0}".format(ret))
        return False, ret


def _check_corner_cases(filepath, expected):
    if not expected:
        ret = {"Success" : "nothing is expected, therefore passing the test", "expected": expected}
        log.info("FDG stat is returning status : True, value : {0}".format(ret))
        return True, ret
    elif 'match_on_file_missing' in expected.keys() and expected['match_on_file_missing']:
        ret = {"Success": "unable to find file, passing check because 'match_on_file_missing' is 'True'", "expected": expected}
        log.info("FDG stat is returning status : True, value : {0}".format(ret))
        return True, ret
    else:
        reason = "Could not get access any file at '{0}'. " \
                 "File might not exist, or hubble might not" \
                 " have enough permissions".format(filepath)
        ret = {'Failure': reason, "expected": expected}
        log.info("FDG stat is returning status : False, value : {0}".format(ret))
        return False, ret


def _validate_inputs(filepath, expected):
    ret = ''
    if filepath is None or filepath == '':
        log.error("filepath not specified")
        ret = {'Failure': "no filepath provided", "expected": expected}
        log.info("FDG stat is returning status : True, value : {0}".format(ret))
        return False, ret

    if 'allow_more_strict' in expected.keys() and 'mode' not in expected.keys():
        reason = "'allow_more_strict' tag can't be specified without 'mode' tag." \
                 " Seems like a bug in hubble profile."
        ret = {'Failure': reason, "expected": expected}
        log.info("FDG stat is returning status : True, value : {0}".format(ret))
        return False, ret

    return True, ret

def _check_mode(max_permission, given_permission, allow_more_strict):
    '''
    Checks whether a file's permission are equal to a given permission or more restrictive.
    Permission is a string of 3 digits [0-7]. 'given_permission' is the actual permission on file,
    'max_permission' is the expected permission on this file. Set 'allow_more_strict' to True,
    to allow more restrictive permissions as well. Example:

    _check_mode('644', '644', False)        returns         True
    _check_mode('644', '600', False)        returns         False
    _check_mode('644', '644', True)         returns         True
    _check_mode('644', '600', True)         returns         True
    _check_mode('644', '655', True)        returns         False

    '''

    if given_permission == '0':
        return True

    if ((not allow_more_strict) or (max_permission == 'None')):
        return (max_permission == given_permission)

    if (_is_permission_in_limit(max_permission[0], given_permission[0]) and
            _is_permission_in_limit(max_permission[1], given_permission[1]) and
            _is_permission_in_limit(max_permission[2], given_permission[2])):
        return True

    return False


def _is_permission_in_limit(max_permission, given_permission):
    '''
    Return true only if given_permission is not more lenient that max_permission. In other words, if
    r or w or x is present in given_permission but absent in max_permission, it should return False
    Takes input two integer values from 0 to 7.
    '''
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
