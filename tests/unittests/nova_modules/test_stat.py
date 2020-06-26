from unittest import TestCase
from unittest.mock import patch
import pytest

from hubblestack.extmods.nova_v2_modules import stat
from hubblestack.utils.hubble_error import AuditCheckValidationError


class TestNovaStat(TestCase):
    """
    Unit tests for stat nova module
    """
    def test_valid_params1(self):
        """
        No mandatory param is passed
        Check should throw exception with an error message
        :return:
        """
        audit_check={}
        check_id = "test-1"

        with pytest.raises(AuditCheckValidationError) as exception:
            stat.validate_params(check_id, audit_check)
            pytest.fail("Check should not have passed")

    def test_valid_params2(self):
        """
        All mandatory param is passed
        Check should run normally
        :return:
        """
        audit_check={'path': '/a/b/c',
                     'gid': '1',
                     'group': 'all',
                     'mode': 'root',
                     'uid': 1,
                     'user': 'root'}
        check_id = "test-2"

        stat.validate_params(check_id, audit_check)

    def test_valid_params3(self):
        """
        All mandatory param except uid is passed
        Check should throw exception with proper message
        :return:
        """
        audit_check={'path': '/a/b/c',
                     'gid': '1',
                     'group': 'all',
                     'mode': 'root',
                     'user': 'root'}
        check_id = "test-3"

        with pytest.raises(AuditCheckValidationError) as exception:
            stat.validate_params(check_id, audit_check)
            pytest.fail("Check should not have passed")
        self.assertTrue('Mandatory parameter: "uid" not found for check-id: test-3' in str(exception.value))

    def test_filtered_logs1(self):
        """
        Check the return value of filtered logs
        :return:
        """
        expected_val ={"path": "/a/b/c",
                       "gid": 1,
                       "uid": 1}
        audit_check = {"path": "/a/b/c",
                       "gid": 1,
                       "uid": 1,
                       "group": "all",
                       "mode": "root",
                       "user": "root"}
        check_id = "test-1"

        ret_val = stat.get_filtered_params_to_log(check_id, audit_check)
        self.assertEqual(expected_val, ret_val)

    def test_execute1(self):
        """
        Execute stat module.
        File is not present. Set success on file missing as true.
        Match output string
        :return:
        """
        expected_val = { "result": True,
                         "output": "File not present and success_on_file_missing flag is true"}
        audit_check = {"path": "/a/b/c",
                       "gid": 1,
                       "uid": 1,
                       "group": "all",
                       "mode": "root",
                       "user": "root",
                       "success_on_file_missing": True}
        check_id = "test-1"

        ret_val = stat.execute(check_id, audit_check)
        self.assertEqual(expected_val, ret_val)

    def test_execute2(self):
        """
        Execute stat module.
        File is not present. Set success on file missing as false.
        Match output string
        :return:
        """
        expected_val = { "result": False,
                         "failure_reason": "File not present"}
        audit_check = {"path": "/a/b/c",
                       "gid": 1,
                       "uid": 1,
                       "group": "all",
                       "mode": "root",
                       "user": "root"}
        check_id = "test-2"
        ret_val = stat.execute(check_id, audit_check)
        self.assertEqual(expected_val, ret_val)

    @patch("os.path.isfile")
    def test_execute3(self, mock_isfile):
        """
        Execute stat module.
        Simple positive case
        :return:
        """
        expected_val = { "result": True}
        audit_check = {"path": "/a/b/c",
                       "gid": 1,
                       "uid": 1,
                       "group": "all",
                       "mode": "644",
                       "user": "root"}
        check_id = "test-3"
        mock_isfile.return_value = True

        def test_fn(name):
            return {"gid": 1,
                    "group": "all",
                    "user": "root",
                    "mode": "0644",
                    "uid": 1}
        __salt__={'file.stats': test_fn}

        stat.__salt__ = __salt__
        ret_val = stat.execute(check_id, audit_check)
        self.assertEqual(expected_val, ret_val)

    @patch("os.path.isfile")
    def test_execute4(self, mock_isfile):
        """
        Execute stat module.
        GID is not matching
        Check should return false and proper error message
        :return:
        """
        expected_val = { "result": False,
                         "failure_reason": {"gid": "Expected: 1, got: 2"}}
        audit_check = {"path": "/a/b/c",
                       "gid": 1,
                       "uid": 1,
                       "group": "all",
                       "mode": "644",
                       "user": "root"}
        check_id = "test-4"
        mock_isfile.return_value = True

        def test_fn(name):
            return {"gid": 2,
                    "group": "all",
                    "user": "root",
                    "mode": "0644",
                    "uid": 1}
        __salt__={'file.stats': test_fn}

        stat.__salt__ = __salt__
        ret_val = stat.execute(check_id, audit_check)
        self.assertEqual(expected_val, ret_val)

    @patch("os.path.isfile")
    def test_execute5(self, mock_isfile):
        """
        Execute stat module.
        group is not matching
        Check should return false and proper error message
        :return:
        """
        expected_val = {"result": False,
                        "failure_reason": {"group": "Expected: all, got: root"}}
        audit_check = {"path": "/a/b/c",
                       "gid": 1,
                       "uid": 1,
                       "group": "all",
                       "mode": "644",
                       "user": "root"}
        check_id = "test-5"
        mock_isfile.return_value = True

        def test_fn(name):
            return {"gid": 1,
                    "group": "root",
                    "user": "root",
                    "mode": "0644",
                    "uid": 1}

        __salt__ = {'file.stats': test_fn}

        stat.__salt__ = __salt__
        ret_val = stat.execute(check_id, audit_check)
        self.assertEqual(expected_val, ret_val)

    @patch("os.path.isfile")
    def test_execute6(self, mock_isfile):
        """
        Execute stat module.
        user is not matching
        Check should return false and proper error message
        :return:
        """
        expected_val = {"result": False,
                        "failure_reason": {"user": "Expected: root, got: test"}}
        audit_check = {"path": "/a/b/c",
                       "gid": 1,
                       "uid": 1,
                       "group": "all",
                       "mode": "644",
                       "user": "root"}
        check_id = "test-6"
        mock_isfile.return_value = True

        def test_fn(name):
            return {"gid": 1,
                    "group": "all",
                    "user": "test",
                    "mode": "0644",
                    "uid": 1}

        __salt__ = {'file.stats': test_fn}

        stat.__salt__ = __salt__
        ret_val = stat.execute(check_id, audit_check)
        self.assertEqual(expected_val, ret_val)

    @patch("os.path.isfile")
    def test_execute7(self, mock_isfile):
        """
        Execute stat module.
        uid is not matching
        Check should return false and proper error message
        :return:
        """
        expected_val = {"result": False,
                        "failure_reason": {"uid": "Expected: 1, got: 2"}}
        audit_check = {"path": "/a/b/c",
                       "gid": 1,
                       "uid": 1,
                       "group": "all",
                       "mode": "644",
                       "user": "root"}
        check_id = "test-7"
        mock_isfile.return_value = True

        def test_fn(name):
            return {"gid": 1,
                    "group": "all",
                    "user": "root",
                    "mode": "0644",
                    "uid": 2}

        __salt__ = {'file.stats': test_fn}

        stat.__salt__ = __salt__
        ret_val = stat.execute(check_id, audit_check)
        self.assertEqual(expected_val, ret_val)

    @patch("os.path.isfile")
    def test_execute8(self, mock_isfile):
        """
        Execute stat module.
        mode is not matching with allow_more_strict set to false
        Check should return false and proper error message
        :return:
        """
        expected_val = {"result": False,
                        "failure_reason": {"mode": "Expected: 600, got: 0644"}}
        audit_check = {"path": "/a/b/c",
                       "gid": 1,
                       "uid": 1,
                       "group": "all",
                       "mode": "600",
                       "user": "root"}
        check_id = "test-8"
        mock_isfile.return_value = True

        def test_fn(name):
            return {"gid": 1,
                    "group": "all",
                    "user": "root",
                    "mode": "0644",
                    "uid": 1}

        __salt__ = {'file.stats': test_fn}

        stat.__salt__ = __salt__
        ret_val = stat.execute(check_id, audit_check)
        self.assertEqual(expected_val, ret_val)

    @patch("os.path.isfile")
    def test_execute9(self, mock_isfile):
        """
        Execute stat module.
        mode is not matching with allow_more_strict set to true
        Check should return false and proper error message
        :return:
        """
        expected_val = {"result": False,
                        "failure_reason": {"mode": "Expected: 600, got: 0644"}}
        audit_check = {"path": "/a/b/c",
                       "gid": 1,
                       "uid": 1,
                       "group": "all",
                       "mode": "600",
                       "user": "root",
                       "allow_more_strict": True}
        check_id = "test-9"
        mock_isfile.return_value = True

        def test_fn(name):
            return {"gid": 1,
                    "group": "all",
                    "user": "root",
                    "mode": "0644",
                    "uid": 1}

        __salt__ = {'file.stats': test_fn}

        stat.__salt__ = __salt__
        ret_val = stat.execute(check_id, audit_check)
        self.assertEqual(expected_val, ret_val)

    @patch("os.path.isfile")
    def test_execute10(self, mock_isfile):
        """
        Execute stat module.
        mode is matching with allow_more_strict set to true
        expected permission is more than given permission on file
        Check should return true
        :return:
        """
        expected_val = {"result": True}
        audit_check = {"path": "/a/b/c",
                       "gid": 1,
                       "uid": 1,
                       "group": "all",
                       "mode": "623",
                       "user": "root",
                       "allow_more_strict": True}
        check_id = "test-10"
        mock_isfile.return_value = True

        def test_fn(name):
            return {"gid": 1,
                    "group": "all",
                    "user": "root",
                    "mode": "0421",
                    "uid": 1}

        __salt__ = {'file.stats': test_fn}

        stat.__salt__ = __salt__
        ret_val = stat.execute(check_id, audit_check)
        self.assertEqual(expected_val, ret_val)

    def test_checkmode1(self):
        """
        Test check mode function
        max_permission is same given_permission
        allow_more_strict is set to false
        should return true
        :return:
        """
        max_permissions = "400"
        given_permissions = "400"
        allow_more_strict = False
        self.assertTrue(stat._check_mode(max_permissions, given_permissions, allow_more_strict))

    def test_checkmode2(self):
        """
        Test check mode function
        max_permission is different than given_permission
        allow_more_strict is set to false
        should return false
        :return:
        """
        max_permissions = "420"
        given_permissions = "400"
        allow_more_strict = False
        self.assertFalse(stat._check_mode(max_permissions, given_permissions, allow_more_strict))

    def test_checkmode3(self):
        """
        Test check mode function
        max_permission is same as given_permission
        allow_more_strict is set to true
        should return true
        :return:
        """
        max_permissions = "420"
        given_permissions = "420"
        allow_more_strict = True
        self.assertTrue(stat._check_mode(max_permissions, given_permissions, allow_more_strict))

    def test_checkmode4(self):
        """
        Test check mode function
        max_permission is less than given_permission
        allow_more_strict is set to true
        should return false
        :return:
        """
        max_permissions = "400"
        given_permissions = "420"
        allow_more_strict = True
        self.assertFalse(stat._check_mode(max_permissions, given_permissions, allow_more_strict))

    def test_checkmode5(self):
        """
        Test check mode function
        max_permission is more than given_permission
        allow_more_strict is set to true
        should return true
        :return:
        """
        max_permissions = "420"
        given_permissions = "400"
        allow_more_strict = True
        self.assertTrue(stat._check_mode(max_permissions, given_permissions, allow_more_strict))

    def test_is_permission_in_limit1(self):
        """
        Test _is_permission_in_limit function
        max_permission is same as given_permission
        should return true
        :return:
        """
        max_permissions = "5"
        given_permissions = "5"
        self.assertTrue(stat._is_permission_in_limit(max_permissions, given_permissions))

    def test_is_permission_in_limit2(self):
        """
        Test _is_permission_in_limit function
        max_permission is more than given_permission
        should return true
        :return:
        """
        max_permissions = "7"
        given_permissions = "5"
        self.assertTrue(stat._is_permission_in_limit(max_permissions, given_permissions))

    def test_is_permission_in_limit3(self):
        """
        Test _is_permission_in_limit function
        max_permission is more than given_permission
        but given permission is not allowed in max_permission
        should return false
        :return:
        """
        max_permissions = "5"
        given_permissions = "2"
        self.assertFalse(stat._is_permission_in_limit(max_permissions, given_permissions))

    def test_is_permission_in_limit4(self):
        """
        Test _is_permission_in_limit function
        max_permission is less given_permission
        should return false
        :return:
        """
        max_permissions = "3"
        given_permissions = "5"
        self.assertFalse(stat._is_permission_in_limit(max_permissions, given_permissions))