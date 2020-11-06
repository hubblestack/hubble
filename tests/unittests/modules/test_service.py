from unittest import TestCase
import pytest

from hubblestack.extmods.hubble_mods import service
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestService(TestCase):
    """
    Unit tests for service module
    """
    def test_invalid_params1(self):
        """
        No mandatory param is passed
        should fail
        """
        block_dict={}
        check_id = "test-1"

        with pytest.raises(HubbleCheckValidationError) as exception:
            service.validate_params(check_id, block_dict, {})
            pytest.fail("Check should not have passed")

    def test_valid_params1(self):
        """
        valid param, should pass
        """
        block_dict={"args": {"name": "test"}}
        check_id = "test-1"

        service.validate_params(check_id, block_dict, {})

    def test_filtered_logs1(self):
        """
        valid param, should pass
        """
        block_dict={"args": {"name": "test234"}}
        check_id = "test-1"

        res = service.get_filtered_params_to_log(check_id, block_dict, {})
        self.assertEqual(res, {"name": "test234"})

    def test_execute1(self):
        """
        Query for a service. Should pass
        """
        def _get_all():
            return ["service1", "service2"]
        def _status(name):
            if name == "service1":
                return True
            elif name == "service2":
                return False
            return True
        def _enabled(name):
            return True
        service.__salt__ = {
            "service.get_all": _get_all,
            "service.status": _status,
            "service.enabled": _enabled
        }
        block_dict={"args": {"name": "service1"}}
        check_id = "test-1"

        status, res = service.execute(check_id, block_dict, {})
        self.assertEqual(res, {"result": [{"name": "service1", "running": True, "enabled": True}]})

    def test_execute2(self):
        """
        Query for a service, match running: False
        """
        def _get_all():
            return ["service1", "service2"]
        def _status(name):
            if name == "service1":
                return True
            elif name == "service2":
                return False
            return True
        def _enabled(name):
            return True
        service.__salt__ = {
            "service.get_all": _get_all,
            "service.status": _status,
            "service.enabled": _enabled
        }
        block_dict={"args": {"name": "service2"}}
        check_id = "test-1"

        status, res = service.execute(check_id, block_dict, {})
        self.assertEqual(res, {"result": [{"name": "service2", "running": False, "enabled": True}]})

    def test_execute3(self):
        """
        Check for '*'
        """
        def _get_all():
            return ["service1", "service2"]
        def _status(name):
            if name == "service1":
                return True
            elif name == "service2":
                return False
            return True
        def _enabled(name):
            return True
        service.__salt__ = {
            "service.get_all": _get_all,
            "service.status": _status,
            "service.enabled": _enabled
        }
        block_dict={"args": {"name": "s*"}}
        check_id = "test-1"

        status, res = service.execute(check_id, block_dict, {})
        self.assertEqual(res, {"result": [
            {"name": "service1", "running": True, "enabled": True},
            {"name": "service2", "running": False, "enabled": True}
            ]})
