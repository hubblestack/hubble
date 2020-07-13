from unittest import TestCase
import pytest

from hubblestack.extmods.nova_v2_modules import fdg
from hubblestack.utils.hubble_error import AuditCheckValidationError

class TestNovaFdg(TestCase):
    """
    Unit tests for fdg nova module
    """
    def test_validateParams1(self):
        """
        Mandatory param not passed
            Test should report failure, 
            Also, check specific exception should be raised
        """
        audit_check = {}
        check_id = "test-1"

        with pytest.raises(AuditCheckValidationError) as exception:
            fdg.validate_params(check_id, audit_check)
            pytest.fail('Should not have passed')
        self.assertTrue('Mandatory parameter: file param not found' in str(exception.value))

    def test_validateParams2(self):
        """
        Mandatory param passed
            Test should pass
        """
        audit_check = {"file": "salt://test"}
        check_id = "test-1"

        fdg.validate_params(check_id, audit_check)

    def test_filteredLogs_1(self):
        """
        Check return value
        """
        filepath = "salt://test.fdg"
        expected_result = {"file": filepath}
        audit_check = {"file": filepath}
        check_id = "test-1"

        ret_val = fdg.get_filtered_params_to_log(check_id, audit_check)
        self.assertTrue(ret_val == expected_result)

    def test_execute_1(self):
        """
        Execute fdg module, Check return value
        """
        filepath = "salt://test.fdg"
        expected_result = {"result": True}
        audit_check = {"file": filepath}
        check_id = "test-1"

        def test_fn(arg1, starting_chained=None):
            return True, (True,True)
        __salt__ = {}
        __salt__['fdg.fdg'] = test_fn

        fdg.__salt__ = __salt__

        ret_val = fdg.execute(check_id, audit_check)
        self.assertTrue(ret_val == expected_result)

    def test_execute_2(self):
        """
        Execute fdg module, Pass use_status attribute via check
        """
        filepath = "salt://test.fdg"
        expected_result = {"result": True}
        audit_check = {"file": filepath, "use_status": True}
        check_id = "test-1"

        def test_fn(arg1, starting_chained=None):
            return True, (True,True)
        __salt__ = {}
        __salt__['fdg.fdg'] = test_fn

        fdg.__salt__ = __salt__

        ret_val = fdg.execute(check_id, audit_check)
        self.assertTrue(ret_val == expected_result)

    def test_execute_3(self):
        """
        Execute fdg module, Pass use_status attribute via check
        Expected False
        """
        filepath = "salt://test.fdg"
        expected_result = {"result": False}
        audit_check = {"file": filepath, "use_status": False}
        check_id = "test-1"

        def test_fn(arg1, starting_chained=None):
            return True, (False,True)
        __salt__ = {}
        __salt__['fdg.fdg'] = test_fn

        fdg.__salt__ = __salt__

        ret_val = fdg.execute(check_id, audit_check)
        self.assertTrue(ret_val == expected_result)
