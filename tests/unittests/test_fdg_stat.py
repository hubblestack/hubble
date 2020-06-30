# coding: utf-8
import logging
import hubblestack.extmods.fdg.stat
import mock
log = logging.getLogger(__name__)


def test_validate_inputs_positive():
    log.info('\n \n Executing test_check_stats_negative_no_filepath')
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
    log.info('\n \n Executing test_check_stats_negative_no_filepath')
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
    log.info('\n \n Executing test_check_stats_negative_no_mode')
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
    log.info('\n \n Executing test_check_stats_positive')
    params = {'params' : {'filepath' : '/etc/passwd',
                          'mode' : '644',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }
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
    log.info('\n \n Executing test_check_stats_positive_using_chained')
    params = {'params' : {'mode' : '644',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }
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
    log.info('\n \n Executing test_check_stats_negative')
    params = {'params' : {'filepath' : '/etc/passwd',
                          'mode' : '400',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }
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
    log.info('\n \n Executing test_check_stats_negative')
    params = {'params' : {'filepath' : '/etc/passwd',
                          'mode' : '644',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'centos',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }
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
    log.info('\n \n Executing test_check_stats_negative')
    params = {'params' : {'filepath' : '/etc/passwd',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }
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

# value of 'allow more strict' is not boolean
def test_check_stats_incorrect_param_type_negative():
    log.info('\n \n Executing test_check_stats_incorrect_param_type_negative')

    params = {'params' : {'filepath' : '/etc/passwd',
                          'mode' : '400',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : "True"
                         }
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
    log.info('\n \n Executing test_check_stats_negative_using_chained')
    params = {'params' : {'mode' : '400',
                          'uid' : 0,
                          'gid' : 0,
                          'user' : 'root',
                          'group' : 'root',
                          'match_on_file_missing' : True,
                          'allow_more_strict' : True
                         }
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
    log.info('\n \n Executing test_check_stats_positive_nothing_expected')
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
    log.info('\n \n Executing test_check_stats_positive_match_on_file_missing')
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
    log.info('\n \n Executing test_check_stats_positive_match_on_file_missing')
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


def test_is_permission_in_limit_positive():
    log.info('\n \n Executing test_is_permission_in_limit_positive')
    val = hubblestack.extmods.fdg.stat._is_permission_in_limit(6, 4)
    assert val


def test_is_permission_in_limit_negative():
    log.info('\n \n Executing test_is_permission_in_limit_negative')
    val = hubblestack.extmods.fdg.stat._is_permission_in_limit(4, 3)
    assert not val


def test_check_mode_positive():
    log.info('\n \n Executing test_check_mode_positive')
    val = hubblestack.extmods.fdg.stat._check_mode("644", "644", False)
    assert val


def test_check_mode_negative():
    log.info('\n \n Executing test_check_mode_negative')
    val = hubblestack.extmods.fdg.stat._check_mode("644", "600", False)
    assert not val


def test_check_mode_positive_allow_more_strict():
    log.info('\n \n Executing test_check_mode_positive_allow_more_strict')
    val = hubblestack.extmods.fdg.stat._check_mode("644", "600", True)
    assert val


def test_check_mode_negative_allow_more_strict():
    log.info('\n \n Executing test_check_mode_negative_allow_more_strict')
    val = hubblestack.extmods.fdg.stat._check_mode("600", "644", True)
    assert not val


def test_check_mode_given_permission_is_zero():
    log.info('\n \n Executing test_check_mode_given_permission_is_zero')
    val = hubblestack.extmods.fdg.stat._check_mode("600", "0", True)
    assert val
