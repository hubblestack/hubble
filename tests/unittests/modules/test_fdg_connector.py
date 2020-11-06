from unittest import TestCase
from unittest.mock import patch
import pytest

from hubblestack.extmods.hubble_mods import fdg
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestFdg(TestCase):
    """
    Unit tests for fdg-connector module
    """
    def test_invalid_params1(self):
        """
        fdg_file not passed, should fail
        """
        block_dict={}
        check_id = "test-1"
        with pytest.raises(HubbleCheckValidationError) as exception:
            fdg.validate_params(check_id, block_dict, {})
            pytest.fail("Check should not have passed")

    def test_valid_params(self):
        """
        all params present, should pass
        """
        block_dict={"args": {"fdg_file": "salt://abc/test.yaml"}}
        check_id = "test-1"
        fdg.validate_params(check_id, block_dict, {})

    def test_filtered_params(self):
        """
        should pass
        """
        block_dict={"args": {"fdg_file": "salt://abc/test.yaml"}}
        check_id = "test-1"

        ret = fdg.get_filtered_params_to_log(check_id, block_dict,{})
        self.assertEqual(ret, {"fdg_file": "salt://abc/test.yaml"})

    def test_execute1(self):
        """
        sample execution, should pass
        """
        block_dict={"args": {"fdg_file": "salt://abc/test.yaml"}}
        check_id = "test-1"

        with patch('hubblestack.extmods.hubble_mods.fdg.runner_factory.get_fdg_runner') as runner_mock:
            runner_mock.return_value.init_loader.return_value = True
            runner_mock.return_value.execute.return_value = ((), ("result", True))

            status, res = fdg.execute(check_id, block_dict, {})
            self.assertEqual(status, True)

    def test_execute2(self):
        """
        Execution failed, status should be False
        """
        block_dict={"args": {"fdg_file": "salt://abc/test.yaml"}}
        check_id = "test-1"

        with patch('hubblestack.extmods.hubble_mods.fdg.runner_factory.get_fdg_runner') as runner_mock:
            runner_mock.return_value.init_loader.return_value = True
            runner_mock.return_value.execute.return_value = ((), ("", False))

            status, res = fdg.execute(check_id, block_dict, {})
            self.assertEqual(status, False)

    def test_execute3(self):
        """
        status=False, got some result.
        use_status=False, should pass as we got some result
        """
        block_dict={"args": {
            "fdg_file": "salt://abc/test.yaml",
            "use_status": False
            }}
        check_id = "test-1"

        with patch('hubblestack.extmods.hubble_mods.fdg.runner_factory.get_fdg_runner') as runner_mock:
            runner_mock.return_value.init_loader.return_value = True
            runner_mock.return_value.execute.return_value = ((), ("test", False))

            status, res = fdg.execute(check_id, block_dict, {})
            self.assertEqual(status, True)

    def test_execute4(self):
        """
        status=False, got some result.
        use_status=False, should pass as we got some result
        """
        block_dict={"args": {
            "fdg_file": "salt://abc/test.yaml",
            "use_status": True
            }}
        check_id = "test-1"

        with patch('hubblestack.extmods.hubble_mods.fdg.runner_factory.get_fdg_runner') as runner_mock:
            runner_mock.return_value.init_loader.return_value = True
            runner_mock.return_value.execute.return_value = ((), [("test", False)])

            status, res = fdg.execute(check_id, block_dict, {})
            self.assertEqual(status, False)

    def test_execute5(self):
        """
        status=False, got some result.
        use_status=False, should pass as we got some result
        """
        block_dict={"args": {
            "fdg_file": "salt://abc/test.yaml",
            "use_status": True,
            "consolidation_operator": "or"
            }}
        check_id = "test-1"

        with patch('hubblestack.extmods.hubble_mods.fdg.runner_factory.get_fdg_runner') as runner_mock:
            runner_mock.return_value.init_loader.return_value = True
            runner_mock.return_value.execute.return_value = ((), [[("test", False)]])

            status, res = fdg.execute(check_id, block_dict, {})
            self.assertEqual(status, False)

    def test_execute6(self):
        """
        status=False, got some result.
        use_status=False, should pass as we got some result
        """
        block_dict={"args": {
            "fdg_file": "salt://abc/test.yaml",
            "use_status": True,
            "consolidation_operator": "or"
            }}
        check_id = "test-1"

        with patch('hubblestack.extmods.hubble_mods.fdg.runner_factory.get_fdg_runner') as runner_mock:
            runner_mock.return_value.init_loader.return_value = True
            runner_mock.return_value.execute.return_value = ((), {"test": False})

            status, res = fdg.execute(check_id, block_dict, {})
            self.assertEqual(status, False)
