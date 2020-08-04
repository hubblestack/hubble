import logging
import hubblestack.utils.stat_functions as stat_functions
import mock

log = logging.getLogger(__name__)


def test_is_permission_in_limit_positive():
    log.info('\n \n Executing test_is_permission_in_limit_positive')
    val = stat_functions._is_permission_in_limit(6, 4)
    assert val


def test_is_permission_in_limit_negative():
    log.info('\n \n Executing test_is_permission_in_limit_negative')
    val = stat_functions._is_permission_in_limit(4, 3)
    assert not val


def test_check_mode_1():
    test_data_max_permission = '644'
    test_data_given_permission = '644'
    test_data_allow_more_strict = True
    expected_val = True
    result = stat_functions.check_mode(test_data_max_permission, test_data_given_permission,
                                       test_data_allow_more_strict)
    assert expected_val == result


def test_check_mode_2():
    test_data_max_permission = '644'
    test_data_given_permission = '644'
    test_data_allow_more_strict = False
    expected_val = True
    result = stat_functions.check_mode(test_data_max_permission, test_data_given_permission,
                                       test_data_allow_more_strict)
    assert expected_val == result


def test_check_mode_3():
    test_data_max_permission = '644'
    test_data_given_permission = '600'
    test_data_allow_more_strict = True
    expected_val = True
    result = stat_functions.check_mode(test_data_max_permission, test_data_given_permission,
                                       test_data_allow_more_strict)
    assert expected_val == result


def test_check_mode_4():
    test_data_max_permission = '644'
    test_data_given_permission = '600'
    test_data_allow_more_strict = False
    expected_val = False
    result = stat_functions.check_mode(test_data_max_permission, test_data_given_permission,
                                       test_data_allow_more_strict)
    assert expected_val == result


def test_check_mode_5():
    test_data_max_permission = '644'
    test_data_given_permission = '655'
    test_data_allow_more_strict = True
    expected_val = False
    result = stat_functions.check_mode(test_data_max_permission, test_data_given_permission,
                                       test_data_allow_more_strict)
    assert expected_val == result