# coding: utf-8
import logging
import hubblestack.extmods.fdg.stat
import hubblestack.utils.stat_functions
import mock
log = logging.getLogger(__name__)


def test_match_stats_positive():
    """
        Everything good.
        :expected: Success
    """
    log.info('Executing test_match_stats_positive')
    params = {'mode' : '644',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }

    file_stats = {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}
    chained = {'file_stats': file_stats, 'filepath': "/etc/docker/daemon.json"}
    hubblestack.utils.stat_functions.check_mode = mock.Mock(return_value=True)
    val = hubblestack.extmods.fdg.stat.match_stats(params=params, chained=chained)
    log.debug("return value is %s", val)
    assert val[0]
    assert isinstance(val[1], dict)
    assert 'Success' in val[1].keys()
    assert 'expected' in val[1].keys()
    assert "all stats matching" in val[1]['Success']


def test_match_stats_negative():
    """
        Mode does not match as expected
        :expected: Failure
    """
    log.info('Executing test_match_stats_negative')
    params = {'mode' : '400',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }
    file_stats = {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0,
                  'target': '/etc/passwd',
                  'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                  'ctime': 1491870657.914388}
    chained = {'file_stats': file_stats, 'filepath': "/etc/docker/daemon.json"}
    hubblestack.utils.stat_functions.check_mode = mock.Mock(return_value=False)
    val = hubblestack.extmods.fdg.stat.match_stats(params=params, chained=chained)
    log.debug("return value is %s", val)
    assert not val[0]
    assert isinstance(val[1], dict)
    assert 'Failure' in val[1].keys()
    assert 'expected' in val[1].keys()
    assert "file stats not matching" in val[1]['Failure']


def test_match_stats_negative_subcheck_failed():
    """
        One of the param 'user' does not match as expected
        :expected: Failure
    """
    log.info('Executing test_match_stats_negative_subcheck_failed')
    params = {'mode' : '644',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'centos',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }

    file_stats = {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}
    chained = {'file_stats': file_stats, 'filepath': "/etc/docker/daemon.json"}
    hubblestack.utils.stat_functions.check_mode = mock.Mock(return_value=False)
    val = hubblestack.extmods.fdg.stat.match_stats(params=params, chained=chained)
    log.debug("return value is %s", val)
    assert not val[0]
    assert isinstance(val[1], dict)
    assert 'Failure' in val[1].keys()
    assert 'expected' in val[1].keys()
    assert "file stats not matching" in val[1]['Failure']


def test_match_stats_negative_invalid_inputs():
    """
        allow_more_strict tag cannot be specified without 'mode' param.
        :expected: Failure
    """
    log.info('Executing test_match_stats_negative_invalid_inputs')
    params = {'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }
    file_stats = {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}
    chained = {'file_stats': file_stats, 'filepath': "/etc/docker/daemon.json"}
    val = hubblestack.extmods.fdg.stat.match_stats(params=params, chained=chained)
    log.debug("return value is %s", val)
    assert not val[0]
    assert isinstance(val[1], dict)
    assert 'Failure' in val[1].keys()
    assert 'expected' in val[1].keys()
    assert "'allow_more_strict' tag can't be specified without 'mode' tag" in val[1]['Failure']


def test_match_stats_positive_no_params():
    """
        No parameters are given,
        :expected: Success, since this is the behaviour if no params are provided
    """
    log.info('Executing test_match_stats_positive_no_params')

    file_stats = {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}
    chained = {'file_stats': file_stats, 'filepath': "random_file_path"}
    val = hubblestack.extmods.fdg.stat.match_stats(chained=chained)
    log.debug("return value is %s", val)
    assert val[0]
    assert isinstance(val[1], dict)
    assert 'Success' in val[1].keys()
    assert "expected params not found, therefore passing the test for chained stats" in val[1]['Success']


def test_match_stats_incorrect_param_type_negative():
    """
        data type of match_on_file_missing is not boolean
        :expected: Failure
    """
    log.info('Executing test_match_stats_incorrect_param_type_negative')

    params = {'mode' : '644',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : "True"
                         }
    file_stats = {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}
    chained = {'file_stats': file_stats, 'filepath': "random_file_path"}
    val = hubblestack.extmods.fdg.stat.match_stats(params=params, chained=chained)
    log.debug("return value is %s", val)
    assert not val[0]
    assert isinstance(val[1], dict)
    assert 'Failure' in val[1].keys()
    assert 'expected' in val[1].keys()
    assert "'allow_more_strict' is not a boolean. Seems like a bug in hubble profile." in val[1]['Failure']


def test_positive_match_on_file_missing():
    """
        file_stats in chained have file_not_found, match_on_file_missing is True
        :expected: Success
    """
    log.info('Executing test_positive_match_on_file_missing')
    params =  {'mode': '644',
                 'uid' : 0,
                 'gid' : 0,
                 'user' : 'root',
                 'group' : 'root',
                 'match_on_file_missing' : True,
                 'allow_more_strict' : True
                }
    file_stats = {"file_not_found" : True}
    chained = {'file_stats': file_stats, 'filepath':'file_not_exists'}
    val = hubblestack.extmods.fdg.stat.match_stats(params=params, chained=chained)
    log.debug("return value is %s", val)
    assert val[0]
    assert isinstance(val[1], dict)
    assert 'Success' in val[1].keys()
    assert 'expected' in val[1].keys()
    assert "file not found, passing test case since 'match_on_file_missing' is set to True" in val[1]['Success']


def test_negative_match_on_file_missing():
    """
    file_stats in chained have file_not_found, match_on_file_missing is False
    :expected: Failure
    """
    log.info('Executing test_negative_match_on_file_missing')
    params = {'mode': '644',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : False,
                          'allow_more_strict' : True
               }
    file_stats = {"file_not_found": True}
    chained = {'file_stats': file_stats, 'filepath': "random_file_path"}
    val = hubblestack.extmods.fdg.stat.match_stats(params=params, chained=chained)
    log.debug("return value is %s", val)
    assert not val[0]
    assert isinstance(val[1], dict)
    assert 'Failure' in val[1].keys()
    assert 'expected' in val[1].keys()
    assert "file not found, failing the test since 'match_on_file_missing' is not set to True" in val[1]['Failure']


def test_negative_no_file_stats():
    """
    file_stats in chained have file_not_found, match_on_file_missing is False
    :expected: Failure
    """
    log.info('Executing test_negative_no_file_stats')
    params = {'mode': '644',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : False,
                          'allow_more_strict' : True
               }
    file_stats = {}
    chained = {'file_stats': file_stats, 'filepath': "random_file_path"}
    val = hubblestack.extmods.fdg.stat.match_stats(params=params, chained=chained)
    log.debug("return value is %s", val)
    assert not val[0]
    assert isinstance(val[1], dict)
    assert 'Failure' in val[1].keys()
    assert 'expected' in val[1].keys()
    assert "No stats found in chaining, unable to match stats" in val[1]['Failure']


def test_negative_no_filepath():
    """
    file_stats in chained have file_not_found, match_on_file_missing is False
    :expected: Failure
    """
    log.info('Executing test_negative_no_file_stats')
    params = {'mode': '644',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : False,
                          'allow_more_strict' : True
               }
    file_stats = {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0,
                  'target': '/etc/passwd',
                  'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                  'ctime': 1491870657.914388}
    chained = {'file_stats': file_stats}
    val = hubblestack.extmods.fdg.stat.match_stats(params=params, chained=chained)
    log.debug("return value is %s", val)
    assert not val[0]
    assert isinstance(val[1], dict)
    assert 'Failure' in val[1].keys()
    assert 'expected' in val[1].keys()
    assert "No filepath found in chaining, unable to match stats" in val[1]['Failure']


def test_get_stats_positive():
    """
    get file stats for a file passed as param
    :expected: Success, file stats
    """
    log.info('Executing test_get_stats_positive')
    __salt__ = {}
    params = {"filepath" : "/Users/muagarwa/hubble/tests/unittests/test_fdg_stat.py"}

    expected_file_stats = {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0,
                'target': '/Users/muagarwa/hubble/tests/unittests/test_fdg_stat.py', 'user': 'root',
                'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322, 'ctime': 1491870657.914388}

    def file_stats(name):
        return expected_file_stats

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    val = hubblestack.extmods.fdg.stat.get_stats(params=params)
    log.debug("return value is %s", val)
    assert val[0]
    assert val[1].get('file_stats') == expected_file_stats


def test_get_stats_negative_file_not_exists():
    """
    get file stats for a file passed as param, but file does not exists
    :expected: Failure, file stats
    """
    log.info('Executing test_get_stats_negative_file_not_exists')
    __salt__ = {}
    params = {"filepath" : "/Users/muagarwa/hubble/tests/unittests/file_not_exists"}

    def file_stats(name):
        return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0,
                'target': '/Users/muagarwa/hubble/tests/unittests/test_fdg_stat.py', 'user': 'root',
                'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322, 'ctime': 1491870657.914388}

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    val = hubblestack.extmods.fdg.stat.get_stats(params=params)
    log.debug("return value is %s", val)
    assert not val[0]
    assert val[1].get('file_stats') == {"file_not_found" : True}


def test_get_stats_positive_filepath_is_chained_dict():
    """
    get file stats for a file passed as chained dictionary
    :expected: Failure, file stats
    """
    log.info('Executing test_get_stats_positive_filepath_is_chained')
    __salt__ = {}
    params = {"filepath" : "/Users/muagarwa/hubble/tests/unittests/test_fdg_stat.py"}

    expected_file_stats = {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0,
                           'target': '/Users/muagarwa/hubble/tests/unittests/test_fdg_stat.py', 'user': 'root',
                           'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322, 'ctime': 1491870657.914388}
    def file_stats(name):
        return expected_file_stats

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    val = hubblestack.extmods.fdg.stat.get_stats(chained=params)
    log.debug("return value is %s", val)
    assert val[0]
    assert val[1].get('file_stats') == expected_file_stats


def test_get_stats_positive_filepath_is_chained_value():
    """
    get file stats for a file passed as param, but file does not exists
    :expected: Failure, file stats
    """
    log.info('Executing test_get_stats_positive_filepath_is_chained')
    __salt__ = {}
    params = "/Users/muagarwa/hubble/tests/unittests/test_fdg_stat.py"

    expected_file_stats = {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0,
                           'target': '/Users/muagarwa/hubble/tests/unittests/test_fdg_stat.py', 'user': 'root',
                           'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322, 'ctime': 1491870657.914388}
    def file_stats(name):
        return expected_file_stats

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    val = hubblestack.extmods.fdg.stat.get_stats(chained=params)
    log.debug("return value is %s", val)
    assert val[0]
    assert val[1].get('file_stats') == expected_file_stats


def test_get_stats_negative_incorrect_format_of_chained():
    """
    chained value is of incorrect format
    :expected: Failure, failure_reason_dict
    """
    log.info('Executing test_get_stats_negative_incorrect_format_of_chained')
    __salt__ = {}
    params = [["/Users/muagarwa/hubble/tests/unittests/test_fdg_stat.py"]]

    expected_file_stats = {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0,
                           'target': '/Users/muagarwa/hubble/tests/unittests/test_fdg_stat.py', 'user': 'root',
                           'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322, 'ctime': 1491870657.914388}
    def file_stats(name):
        return expected_file_stats

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    val = hubblestack.extmods.fdg.stat.get_stats(chained=params)
    log.debug("return value is %s", val)
    assert not val[0]
    assert "value of chained is not in correct format" in val[1].get('Failure')


def test_get_stats_negative_no_params():
    """
    No Params are provided
    :expected: Failure, failure_reason_dict
    """
    log.info('Executing test_get_stats_negative_no_params')
    val = hubblestack.extmods.fdg.stat.get_stats()
    log.debug("return value is %s", val)
    assert not val[0]
    assert "No filepath provided in get_stats, returning False" in val[1].get('Failure')
