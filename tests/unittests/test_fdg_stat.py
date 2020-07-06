# coding: utf-8
import logging
import hubblestack.extmods.fdg.stat
import mock
log = logging.getLogger(__name__)


def test_validate_inputs_positive():
    """
        All parameters given as expected
        :expected: Success
    """
    log.info('Executing test_check_stats_negative_no_filepath')
    expected = { 'mode' : '400',
                  'uid' : 0,
                  'gid' : 0,
                  'user' : 'root',
                  'group' : 'root',
                  'match_on_file_missing' : True,
                  'allow_more_strict' : True
                }
    __salt__ = {}

    def file_stats(name):
        return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    val = hubblestack.extmods.fdg.stat._validate_inputs('/etc/passwd', expected)
    assert val[0]



def test_validate_inputs_negative_no_filepath():
    """
        'filepath' is not given
        :expected: Failure
    """
    log.info('Executing test_check_stats_negative_no_filepath')
    expected = {'mode' : '400',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }
    __salt__ = {}

    def file_stats(name):
        return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    val = hubblestack.extmods.fdg.stat._validate_inputs('', expected)
    assert not val[0]
    assert isinstance(val[1], dict)
    assert 'Failure' in val[1].keys()
    assert 'expected' in val[1].keys()


def test_validate_inputs_negative_no_mode():
    """
        'mode' is not given
        :expected: Failure
    """
    log.info('Executing test_check_stats_negative_no_mode')
    expected = {'filepath' : '/etc/passwd',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }
    __salt__ = {}

    def file_stats(name):
        return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    val = hubblestack.extmods.fdg.stat._validate_inputs('/etc/passwd', expected)
    assert not val[0]
    assert isinstance(val[1], dict)
    assert 'Failure' in val[1].keys()
    assert 'expected' in val[1].keys()


def test_check_stats_positive():
    """
        Filepath is passes as a param, everything good.
        :expected: Success
    """
    log.info('Executing test_check_stats_positive')
    params = {'filepath' : '/etc/passwd',
                          'mode' : '644',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }
    __salt__ = {}

    def file_stats(name):
        return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    valid_inputs = True, ''
    hubblestack.extmods.fdg.stat._validate_inputs = mock.Mock(return_value=valid_inputs)
    val = hubblestack.extmods.fdg.stat.check_stats(params = params)
    assert val[0]
    assert isinstance(val[1], dict)
    assert 'Success' in val[1].keys()
    assert 'expected' in val[1].keys()


def test_check_stats_positive_using_chained():
    """
        Filepath is passed through chaining, everything good
        :expected: Success
    """
    log.info('Executing test_check_stats_positive_using_chained')
    params = {'mode' : '644',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }
    __salt__ = {}

    def file_stats(name):
        return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    valid_inputs = True, ''
    hubblestack.extmods.fdg.stat._validate_inputs = mock.Mock(return_value=valid_inputs)
    val = hubblestack.extmods.fdg.stat.check_stats(params = params, chained={'filepath' : '/etc/passwd'})
    assert val[0]
    assert isinstance(val[1], dict)
    assert 'Success' in val[1].keys()
    assert 'expected' in val[1].keys()


def test_check_stats_negative():
    """
        Filepath is passed from params, but mode does not match as expected
        :expected: Failure
    """
    log.info('Executing test_check_stats_negative')
    params = {'filepath' : '/etc/passwd',
                          'mode' : '400',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }
    __salt__ = {}

    def file_stats(name):
        return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    valid_inputs = True, ''
    hubblestack.extmods.fdg.stat._validate_inputs = mock.Mock(return_value=valid_inputs)
    val = hubblestack.extmods.fdg.stat.check_stats(params=params)
    assert not val[0]
    assert isinstance(val[1], dict)
    assert 'Failure' in val[1].keys()
    assert 'expected' in val[1].keys()

def test_check_stats_negative_subcheck_failed():
    """
        One of the param 'user' does not match as expected
        :expected: Failure
    """
    log.info('Executing test_check_stats_negative')
    params = {'filepath' : '/etc/passwd',
                          'mode' : '644',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'centos',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }
    __salt__ = {}

    def file_stats(name):
        return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    valid_inputs = True, ''
    hubblestack.extmods.fdg.stat._validate_inputs = mock.Mock(return_value=valid_inputs)
    val = hubblestack.extmods.fdg.stat.check_stats(params=params)
    assert not val[0]
    assert isinstance(val[1], dict)
    assert 'Failure' in val[1].keys()
    assert 'expected' in val[1].keys()


def test_check_stats_negative_invalid_inputs():
    """
        match_on_file_missing and allow_more_strict Parameters types are incorrect
        :expected: Failure
    """
    log.info('Executing test_check_stats_negative')
    params = {'filepath' : '/etc/passwd',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }
    __salt__ = {}

    def file_stats(name):
        return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    valid_inputs = False, {"Failure":"reason", "expected":"expectation"}
    hubblestack.extmods.fdg.stat._validate_inputs = mock.Mock(return_value=valid_inputs)
    val = hubblestack.extmods.fdg.stat.check_stats(params=params)
    assert not val[0]
    assert isinstance(val[1], dict)
    assert 'Failure' in val[1].keys()
    assert 'expected' in val[1].keys()


def test_check_stats_negative_no_params():
    """
        No parameters are given
        :expected: Failure
    """
    log.info('Executing test_check_stats_negative_no_params')
    __salt__ = {}

    def file_stats(name):
        return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    valid_inputs = False, {"Failure":"reason", "expected":"expectation"}
    hubblestack.extmods.fdg.stat._validate_inputs = mock.Mock(return_value=valid_inputs)
    val = hubblestack.extmods.fdg.stat.check_stats()
    assert not val[0]
    assert isinstance(val[1], dict)
    assert 'Failure' in val[1].keys()


# value of 'allow more strict' is not boolean
def test_check_stats_incorrect_param_type_negative():
    """
        data type of match_on_file_missing is not boolean
        :expected: Failure
    """
    log.info('Executing test_check_stats_incorrect_param_type_negative')

    params = {'filepath' : '/etc/passwd',
                          'mode' : '400',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : "True"
                         }
    __salt__ = {}

    def file_stats(name):
        return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    valid_inputs = True, ''
    hubblestack.extmods.fdg.stat._validate_inputs = mock.Mock(return_value=valid_inputs)
    val = hubblestack.extmods.fdg.stat.check_stats(params=params)
    assert not val[0]
    assert isinstance(val[1], dict)
    assert 'Failure' in val[1].keys()
    assert 'expected' in val[1].keys()


def test_check_stats_negative_using_chained():
    """
        filepath is passed through FDG chaining, however expected value of mode is different than what is mocked.
        :expected: Failure
    """
    log.info('Executing test_check_stats_negative_using_chained')
    params = {'mode' : '400',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }
    __salt__ = {}

    def file_stats(name):
        return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    valid_inputs = True, ''
    hubblestack.extmods.fdg.stat._validate_inputs = mock.Mock(return_value=valid_inputs)
    val = hubblestack.extmods.fdg.stat.check_stats(params=params, chained={'filepath' : '/etc/passwd'})
    assert not val[0]
    assert isinstance(val[1], dict)
    assert 'Failure' in val[1].keys()
    assert 'expected' in val[1].keys()


def test_check_corner_cases_positive_nothing_expected():
    """
        Filepath is given, but no parameters to match are given.
        :expected: Success
    """
    log.info('Executing test_check_stats_positive_nothing_expected')
    __salt__ = {}

    def file_stats(name):
        return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    val = hubblestack.extmods.fdg.stat._check_corner_cases('/etc/file_not_exists', {})
    assert val[0]
    assert isinstance(val[1], dict)
    assert 'Success' in val[1].keys()
    assert 'expected' in val[1].keys()


def test_check_corner_cases_positive_match_on_file_missing():
    """
        filepath is not given, and match_on_file_missing is True
        :expected: Success
    """
    log.info('Executing test_check_stats_positive_match_on_file_missing')
    expected =  {'mode': '644',
                 'uid' : 0,
                 'gid' : 0,
                 'user' : 'root',
                 'group' : 'root',
                 'match_on_file_missing' : True,
                 'allow_more_strict' : True
                }
    __salt__ = {}

    def file_stats(name):
        return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    val = hubblestack.extmods.fdg.stat._check_corner_cases('/etc/file_does_not_exists', expected)
    assert val[0]
    assert isinstance(val[1], dict)
    assert 'Success' in val[1].keys()
    assert 'expected' in val[1].keys()


def test_check_corner_cases_negative_match_on_file_missing():
    """
    filepath is not given, and match_on_file_missing is False
    :expected: Failure
    """
    log.info('Executing test_check_stats_positive_match_on_file_missing')
    expected = {'mode': '644',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : False,
                          'allow_more_strict' : True
               }
    __salt__ = {}

    def file_stats(name):
        return {'size': 26, 'group': 'root', 'uid': 0, 'type': 'file', 'mode': '0644', 'gid': 0, 'target': '/etc/passwd',
                'user': 'root', 'mtime': 1486511757.0, 'atime': 1507221810.408013, 'inode': 1322,
                'ctime': 1491870657.914388}

    __salt__['file.stats'] = file_stats
    hubblestack.extmods.fdg.stat.__salt__ = __salt__
    val = hubblestack.extmods.fdg.stat._check_corner_cases('/etc/file_does_not_exists', expected)
    assert not val[0]
    assert isinstance(val[1], dict)
    assert 'Failure' in val[1].keys()
    assert 'expected' in val[1].keys()
