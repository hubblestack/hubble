from unittest import TestCase
import pytest

from hubblestack.extmods.hubble_mods import sysctl
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestSysctl(TestCase):
    """
    Unit tests for sysctl module
    """
    def test_invalid_params1(self):
        """
        No mandatory param is passed
        should fail
        """
        block_dict={}
        check_id = "test-1"

        with pytest.raises(HubbleCheckValidationError) as exception:
            sysctl.validate_params(check_id, block_dict, {})
            pytest.fail("Check should not have passed")

    def test_valid_params1(self):
        """
        valid param, should pass
        """
        block_dict={"args": {"name": "vm.zone_reclaim_mode"}}
        check_id = "test-2"

        sysctl.validate_params(check_id, block_dict, {})

    def test_filtered_logs1(self):
        """
        valid param, should pass
        """
        block_dict={"args": {"name": "vm.zone_reclaim_mode"}}
        check_id = "test-3"

        res = sysctl.get_filtered_params_to_log(check_id, block_dict, {})
        self.assertEqual(res, {"name": "vm.zone_reclaim_mode"})

    def test_execute1(self):
        """
        Query for a kernel param. Should pass
        """
        def _get(name):
            return "0"
        sysctl.__salt__ = {
            "sysctl.get": _get
        }
        block_dict={"args": {"name": "vm.zone_reclaim_mode"}}
        check_id = "test-4"

        status, res = sysctl.execute(check_id, block_dict, {})
        self.assertTrue(status)
        self.assertEqual(res, {"result": {"vm.zone_reclaim_mode": "0"}})

    def test_execute2(self):
        """
        Query for a kernel param.
        Param not available in kernel.
        Should return false
        """
        def _get(name):
            return None
        sysctl.__salt__ = {
            "sysctl.get": _get
        }
        block_dict={"args": {"name": "vm.zone_reclaim_mode"}}
        check_id = "test-5"

        status, res = sysctl.execute(check_id, block_dict, {})
        self.assertFalse(status)
        self.assertEqual(res, {"error": "Could not find attribute vm.zone_reclaim_mode in the kernel"})

    def test_execute3(self):
        """
        Query for a kernel param.
        Param not available in kernel.
        Should return false
        """

        def _get(name):
            return "Error: invalid value"

        sysctl.__salt__ = {
            "sysctl.get": _get
        }
        block_dict={"args": {"name": "vm.zone_reclaim_mode"}}
        check_id = "test-6"

        status, res = sysctl.execute(check_id, block_dict, {})
        self.assertFalse(status)
        self.assertEqual(res, {"error": "An error occurred while reading the value of kernel attribute vm.zone_reclaim_mode"})