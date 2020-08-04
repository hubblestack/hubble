"""
HubbleStack FDG module for using stat to verify ownership & permissions.

1. Sample FDG profile, to get file stats
This profile will fetch file stats for file provided as args, and send the stats to splunk
*****************************************************
main:
    module: stat.get_stats
    args:
        - filepath: "/etc/docker/daemon.json"

*****************************************************

2. Sample FDG profile, with inline comments:
*****************************************************
main:                             # start of this profile's main module
    module: stat.get_stats        # get stats of file provided via args
    args:
        - filepath: "/etc/docker/daemon.json"
    pipe:
        match_stats               # the stats of file are passed as chained param to match_stats module

match_stats
    module: stat.match_stats      # this tells FDG to call stat submodule's match_stats function
    args:                         # arguments to match_stats function
        - mode: 644
          gid: 0
          group: root
          uid: 0
          user: root
          allow_more_strict: True
          match_on_file_missing: True
*****************************************************

3. Sample FDG profile, with inline comments:
This profile chains the stat module, so that some other module can pass filepath to stat module.
*****************************************************
main:                           # start of this profile's main module
    module: osquery.query       # this tells FDG to call osquery submodule's query function
    args:
       - 'select path as filepath from FILE where path="/etc/docker/daemon.json";'
    pipe:                      # This tells FDG to pass the output of the above query to match_stats functions of this profile
       match_stats

match_stats:                    # this profile's check_stats module
    module: stat.match_stats   # this tells FDG to call stat submodule's check_stats function
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
import hubblestack.utils.stat_functions as stat_functions
import salt.utils
import salt.utils.platform
import os
log = logging.getLogger(__name__)


def get_stats(params='', chained=None, chained_status=None):
    """
    :param params: Can contain 'filepath' to fetch stats
    :param chained: file path for which stats are to be fetched
    :param chained_status: Status returned by the chained function.
    :return: tuple with (status(Boolean), result(dict))
    The function will fetch file stats for a file passed either using a previously chained
    function or if a file path is directly passed through params
    """
    if chained:
        log.info("value of 'chained' is not null, using %s value as filepath", chained)
        if isinstance(chained, dict):
            for key, value in chained.items():
                filepath = value
        elif isinstance(chained, str):
            filepath = chained
        else:
            error_msg = "value of chained is not in correct format : {0}".format(chained)
            log.error(error_msg)
            ret = {"Failure" : error_msg}
            return False, ret
    else:
        if not params:
            error_msg = "No filepath provided in get_stats, returning False"
            log.error(error_msg)
            ret = {"Failure": error_msg}
            return False, ret

        filepath = params.get('filepath')

    salt_ret = {}
    log.info("checking stats of %s", filepath)
    salt_ret['filepath'] = filepath
    if os.path.exists(filepath):
        salt_ret['file_stats'] = __salt__['file.stats'](filepath)
    else:
        log.info("file %s not found", filepath)
        ret = {"file_not_found" : True}
        salt_ret['file_stats'] = ret
        return False, salt_ret

    return True, salt_ret


def match_stats(params='', chained=None, chained_status=None):
    """
    :param params: dictionary of parameters to match with the file stats
    :param chained: actual file stats
    :param chained_status: Status returned by the chained function.
    :return: tuple with (status(Boolean), result(dict))
    This function takes into input stat params that are to be matched with actual stats given as chained value.
    """

    if chained and chained.get('file_stats'):
        log.info("value of 'chained' is %s, using these value as file stats", chained.get('file_stats'))
        print("value of 'chained' is %s, using these value as file stats", chained.get('file_stats'))
        file_stats = chained.get('file_stats')
    else:
        log.info("No stats found in chaining, unable to match stats")
        ret = {"Failure": "No stats found in chaining, unable to match stats", "expected" : params}
        return False, ret

    if chained and chained.get('filepath'):
        log.info("value of 'chained' is %s, using this value as file path", chained.get('filepath'))
        print("value of 'chained' is %s, using these value as file path", chained.get('filepath'))
        filepath = chained.get('filepath')
    else:
        log.info("No filepath found in chaining, unable to match stats")
        ret = {"Failure": "No filepath found in chaining, unable to match stats", "expected": params}
        return False, ret

    log.debug("file stats are %s", file_stats)

    if not params:
        log.info("FDG stat's match_stats function is returning status : True, value : %s", file_stats)
        success_msg = "expected params not found, therefore passing the test for chained stats {0}".format(file_stats)
        ret = {"Success": success_msg}
        return True, ret

    expected = {}
    for attribute in ['mode', 'user', 'uid', 'group', 'gid', 'allow_more_strict', 'match_on_file_missing']:
        if attribute in params.keys():
            expected[attribute] = params[attribute]

    if 'match_on_file_missing' in expected.keys() and expected['match_on_file_missing'] \
            and file_stats.get("file_not_found"):
        ret = {"Success": "file not found, passing test case since 'match_on_file_missing' is set to True", "expected": expected, "file": filepath}
        log.info("FDG stat's match_stats function is returning status : True, value : %s", ret)
        return True, ret
    elif file_stats.get("file_not_found"):
        ret = {"Failure": "file not found, failing the test since 'match_on_file_missing' is not set to True",
               "expected": expected, "file": filepath}
        log.info("FDG stat's match_stats function is returning status : False, value : %s", ret)
        return False, ret

    if 'allow_more_strict' in expected and 'mode' not in expected:
        reason = "'allow_more_strict' tag can't be specified without 'mode' tag." \
                 " Seems like a bug in hubble profile."
        ret = {'Failure': reason, "expected": expected, "file": filepath}
        log.info("FDG stat's match_stats function is returning status : False, value : %s", ret)
        return False, ret

    passed = True
    reason_dict = {}
    for attribute in expected.keys():
        if attribute == 'allow_more_strict' or attribute == 'match_on_file_missing':
            continue
        file_attribute_value = file_stats[attribute]

        if attribute == 'mode':
            if file_attribute_value != '0':
                file_attribute_value = file_attribute_value[1:]
            allow_more_strict = expected.get('allow_more_strict', False)
            if not isinstance(allow_more_strict, bool):
                passed = False
                reason = "'allow_more_strict' is not a boolean. Seems like a bug in hubble profile."
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
        ret = {'Failure': "file stats not matching : {0}".format(reason_dict), "expected": expected, "file": filepath}

    if passed:
        ret = {"Success": "all stats matching", "expected": expected, "file": filepath}
        log.info("FDG stat's match_stats function is returning status : True, value : %s", ret)
        return True, ret
    else:
        log.info("FDG stat's match_stats function is returning status : False, value : %s", ret)
        return False, ret
