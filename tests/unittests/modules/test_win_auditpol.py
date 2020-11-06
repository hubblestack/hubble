from unittest import TestCase
from unittest.mock import patch
import pytest

from hubblestack.extmods.hubble_mods import win_auditpol
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestWinAuditpol(TestCase):
    """
    Unit tests for win_auditpol module
    """

    def test_invalid_params1(self):
        """
        No mandatory param is passed
        should fail
        """
        block_dict = {}
        check_id = "test-1"

        with pytest.raises(HubbleCheckValidationError) as exception:
            win_auditpol.validate_params(check_id, block_dict, {})
            pytest.fail("Check should not have passed")

    def test_valid_params1(self):
        """
        valid param, should pass
        """
        block_dict = {"args": {"name": "test"}}
        check_id = "test-2"

        win_auditpol.validate_params(check_id, block_dict, {})

    def test_filtered_logs1(self):
        """
        valid param, should pass
        """
        block_dict = {"args": {"name": "test234"}}
        check_id = "test-3"

        res = win_auditpol.get_filtered_params_to_log(check_id, block_dict, {})
        self.assertEqual(res, {"name": "test234"})

    @patch('hubblestack.extmods.hubble_mods.win_auditpol._auditpol_import')
    def test_execute1(self, mockWinAuditpol):
        """
        Positive case. Policy name exists in auditpol output
        """

        block_dict = {"args": {"name": "test1"}}
        check_id = "test-4"
        mockWinAuditpol.return_value = {"test1": "sample value", "test2": "sample description"}

        status, res = win_auditpol.execute(check_id, block_dict, {})
        self.assertTrue(status)
        self.assertEqual(res, {"result": {"test1": "sample value"}})

    @patch('hubblestack.extmods.hubble_mods.win_auditpol._auditpol_import')
    def test_execute2(self, mockWinAuditpol):
        """
        Positive case. Policy name does not exist in auditpol output
        """

        block_dict = {"args": {"name": "test11"}}
        check_id = "test-5"
        mockWinAuditpol.return_value = {"test1": "sample value", "test2": "sample description"}

        status, res = win_auditpol.execute(check_id, block_dict, {})
        self.assertFalse(status)
        self.assertEqual(res, {"error": "policy_not_found"})
