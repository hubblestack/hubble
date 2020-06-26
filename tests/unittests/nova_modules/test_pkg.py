from unittest import TestCase, mock
import pytest

from hubblestack.extmods.nova_v2_modules import pkg
from hubblestack.utils.hubble_error import AuditCheckValidationError

class TestNovaPkg(TestCase):
    def test_validateParams1(self):
        """
        Mandatory param not passed
            Test should report failure, 
            Also, check specific exception should be raised
        """
        audit_check = {}
        check_id = "test-1"

        with pytest.raises(AuditCheckValidationError) as exception:
            pkg.validate_params(check_id, audit_check)
            pytest.fail('Should not have passed')
        self.assertTrue('Mandatory parameter name is not present' in str(exception.value))

    def test_validateParams2(self):
        """
        Mandatory param passed
            Test should pass
        """
        audit_check = {"name": "splunk"}
        check_id = "test-1"

        pkg.validate_params(check_id, audit_check)

    def test_filteredLogs_1(self):
        """
        Check return value
        """
        expected_result = {"name": "splunk"}
        audit_check = {"name": "splunk"}
        check_id = "test-1"

        ret_val = pkg.get_filtered_params_to_log(check_id, audit_check)
        self.assertTrue(ret_val == expected_result)

    def test_execute_1(self):
        """
        Execute pkg module, Check return value
        package is installed
        """
        expected_result = {"result": True}
        audit_check = {"name": "splunk"}
        check_id = "test-1"

        def testFn(pkg_name):
            return "1.2.1"
        __salt__ = {}
        __salt__['pkg.version'] = testFn

        pkg.__salt__ = __salt__

        ret_val = pkg.execute(check_id, audit_check)
        self.assertTrue(ret_val == expected_result)

    def test_execute_2(self):
        """
        Execute pkg module, Check return value
        Package not installed
        """
        audit_check = {"name": "splunk"}
        check_id = "test-1"

        def testFn(pkg_name):
            return None
        __salt__ = {}
        __salt__['pkg.version'] = testFn

        pkg.__salt__ = __salt__

        ret_val = pkg.execute(check_id, audit_check)
        self.assertFalse(ret_val['result'])

    def test_execute_3(self):
        """
        Execute pkg module, Check return value
        Package installed, version comparison also passed
        And version condition matches, should pass
        """
        audit_check = {"name": "splunk", "version": "1.3.4"}
        check_id = "test-1"

        def testFn(pkg_name):
            return "1.3.4"
        __salt__ = {}
        __salt__['pkg.version'] = testFn

        pkg.__salt__ = __salt__

        ret_val = pkg.execute(check_id, audit_check)
        self.assertTrue(ret_val['result'])

    def test_execute_4(self):
        """
        Execute pkg module, Check return value
        Package installed, version comparison also passed
        And version condition NOT-matches, should Fail
        """
        audit_check = {"name": "splunk", "version": "1.3.4"}
        check_id = "test-1"

        def testFn(pkg_name):
            return "1.3.5"
        __salt__ = {}
        __salt__['pkg.version'] = testFn

        pkg.__salt__ = __salt__

        ret_val = pkg.execute(check_id, audit_check)
        self.assertFalse(ret_val['result'])

    def test_execute_5(self):
        """
        Execute pkg module, Check return value
        Package installed, version comparison also passed, with Comparison operator passed (>=)
        And version condition matches, should Pass
        """
        audit_check = {"name": "splunk", "version": ">=1.3.4"}
        check_id = "test-1"

        def testFn(pkg_name):
            return "1.3.5"
        __salt__ = {}
        __salt__['pkg.version'] = testFn

        pkg.__salt__ = __salt__

        ret_val = pkg.execute(check_id, audit_check)
        self.assertTrue(ret_val['result'])

    def test_execute_6(self):
        """
        Execute pkg module, Check return value
        Package installed, version comparison also passed, with Comparison operator passed (>)
        And version condition matches, should Pass
        """
        audit_check = {"name": "splunk", "version": ">1.3.4"}
        check_id = "test-1"

        def testFn(pkg_name):
            return "1.3.5"
        __salt__ = {}
        __salt__['pkg.version'] = testFn

        pkg.__salt__ = __salt__

        ret_val = pkg.execute(check_id, audit_check)
        self.assertTrue(ret_val['result'])

    def test_execute_7(self):
        """
        Execute pkg module, Check return value
        Package installed, version comparison also passed, with Comparison operator passed (<=)
        And version condition matches, should Fail
        """
        audit_check = {"name": "splunk", "version": "<=1.3.4"}
        check_id = "test-1"

        def testFn(pkg_name):
            return "1.3.5"
        __salt__ = {}
        __salt__['pkg.version'] = testFn

        pkg.__salt__ = __salt__

        ret_val = pkg.execute(check_id, audit_check)
        self.assertFalse(ret_val['result'])

    def test_execute_8(self):
        """
        Execute pkg module, Check return value
        Package installed, version comparison also passed, with Comparison operator passed (<)
        And version condition matches, should Fail
        """
        audit_check = {"name": "splunk", "version": "<1.3.4"}
        check_id = "test-1"

        def testFn(pkg_name):
            return "1.3.5"
        __salt__ = {}
        __salt__['pkg.version'] = testFn

        pkg.__salt__ = __salt__

        ret_val = pkg.execute(check_id, audit_check)
        self.assertFalse(ret_val['result'])

