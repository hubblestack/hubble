from unittest import TestCase
import pytest

from hubblestack.extmods.nova_v2_modules import sysctl
from hubblestack.utils.hubble_error import AuditCheckValidationError


class TestNovaSysctl(TestCase):
    """
    Unit tests for sysctl nova module
    """
    def test_validParams1(self):
        """
        No Mandatory param is passed.
        Check should return error and exception should be raised
        :return:
        """
        audit_check = {}
        check_id = "test-1"

        with pytest.raises(AuditCheckValidationError) as exception:
            sysctl.validate_params(check_id, audit_check)
            pytest.fail("Check should not have passed")

    def test_validParams2(self):
        """
        Mandatory param name is not passed.
        Check should return error and exception should be raised
        :return:
        """
        audit_check = {'match_output': '1'}
        check_id = "test-2"

        with pytest.raises(AuditCheckValidationError) as exception:
            sysctl.validate_params(check_id, audit_check)
            pytest.fail("Check should not have passed")

    def test_validParams3(self):
        """
        Mandatory param match_output is not passed.
        Check should return error and exception should be raised
        :return:
        """
        audit_check = {'name': 'test'}
        check_id = "test-3"

        with pytest.raises(AuditCheckValidationError) as exception:
            sysctl.validate_params(check_id, audit_check)
            pytest.fail("Check should not have passed")

    def test_validParams4(self):
        """
        Mandatory param name and match_output is passed.
        Check should return success
        :return:
        """
        audit_check = { 'name' : 'test',
            'match_output': '1'}
        check_id = "test-4"

        sysctl.validate_params(check_id, audit_check)

    def test_filtered_logs1(self):
        """
        Check the return value of filtered logs
        :return:
        """
        expected_result = {"name": "test"}
        audit_check = {"name": "test"}
        check_id = "test-1"

        return_val = sysctl.get_filtered_params_to_log(check_id, audit_check)
        self.assertEqual(expected_result, return_val)

    def test_execute1(self):
        """
        Execute sysctl module. Check return value
        Match output string.
        Simple positive case
        :return:
        """
        expected_result = {"result": True}
        audit_check = {"name": "test",
                       "match_output": "dummy"}
        check_id = "test-1"

        def test_fn(name):
            return "dummy"
        __salt__={'sysctl.get': test_fn}

        sysctl.__salt__ = __salt__
        ret_val = sysctl.execute(check_id, audit_check)
        self.assertEqual(expected_result, ret_val)

    def test_execute2(self):
        """
        Execute sysctl module. Check return value
        Match output string.
        Simple positive case with regex
        :return:
        """
        expected_result = {"result": True}
        audit_check = {"name": "test",
                       "match_output": "dum*",
                       "match_output_regex": True}
        check_id = "test-2"

        def test_fn(name):
            return "dummy"
        __salt__={'sysctl.get': test_fn}

        sysctl.__salt__ = __salt__
        ret_val = sysctl.execute(check_id, audit_check)
        self.assertEqual(expected_result, ret_val)

    def test_execute3(self):
        """
        Execute sysctl module. Check return value
        Return value not matching.
        Should return false with proper error message.
        :return:
        """
        expected_result = {"result": False,
                           "failure_reason": "Current value of kernel attribute test is dummy It should be set to dum*"}
        audit_check = {"name": "test",
                       "match_output": "dum*"}
        check_id = "test-3"

        def test_fn(name):
            return "dummy"
        __salt__={'sysctl.get': test_fn}

        sysctl.__salt__ = __salt__
        ret_val = sysctl.execute(check_id, audit_check)
        self.assertEqual(expected_result, ret_val)

    def test_execute4(self):
        """
        Execute sysctl module. Check return value
        Pattern not matching with regex.
        Should return false with proper error message.
        :return:
        """
        expected_result = {"result": False,
                           "failure_reason": "Current value of kernel attribute test is dummy It is not matching with regex: ab*"}
        audit_check = {"name": "test",
                       "match_output": "ab*",
                       "match_output_regex": True}
        check_id = "test-4"

        def test_fn(name):
            return "dummy"
        __salt__={'sysctl.get': test_fn}

        sysctl.__salt__ = __salt__
        ret_val = sysctl.execute(check_id, audit_check)
        self.assertEqual(expected_result, ret_val)

    def test_execute5(self):
        """
        Execute sysctl module.
        Match output string.
        Error string returned.
        Should return false with proper error message.
        :return:
        """
        expected_result = {"result": False,
                           "failure_reason": "An error occurred while reading the value of kernel attribute test"}
        audit_check = {"name": "test",
                       "match_output": "dum*",
                       "match_output_regex": True}
        check_id = "test-5"

        def test_fn(name):
            return "Error: Not able to get result"
        __salt__={'sysctl.get': test_fn}

        sysctl.__salt__ = __salt__
        ret_val = sysctl.execute(check_id, audit_check)
        self.assertEqual(expected_result, ret_val)

    def test_execute6(self):
        """
        Execute sysctl module.
        Match output string.
        No result is shown
        Should return false with proper error message.
        :return:
        """
        expected_result = {"result": False,
                           "failure_reason": "Could not find attribute test in the kernel"}
        audit_check = {"name": "test",
                       "match_output": "dum*",
                       "match_output_regex": True}
        check_id = "test-6"

        def test_fn(name):
            return None
        __salt__={'sysctl.get': test_fn}

        sysctl.__salt__ = __salt__
        ret_val = sysctl.execute(check_id, audit_check)
        self.assertEqual(expected_result, ret_val)

    def test_execute7(self):
        """
        Execute sysctl module.
        Match output string.
        No such file or directory is coming in result
        Should return false with proper error message.
        :return:
        """
        expected_result = {"result": False,
                           "failure_reason": "Could not find attribute test in the kernel"}
        audit_check = {"name": "test",
                       "match_output": "dum*",
                       "match_output_regex": True}
        check_id = "test-6"

        def test_fn(name):
            return "---No such file or directory---"
        __salt__={'sysctl.get': test_fn}

        sysctl.__salt__ = __salt__
        ret_val = sysctl.execute(check_id, audit_check)
        self.assertEqual(expected_result, ret_val)