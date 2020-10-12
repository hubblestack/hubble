from unittest import TestCase
from unittest.mock import patch
import pytest

from hubblestack.extmods.hubble_mods import stat
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestStat(TestCase):
    """
    Unit tests for stat module
    """
    def test_invalid_params1(self):
        """
        No mandatory param is passed
        should fail
        """
        block_dict={}
        check_id = "test-1"

        with pytest.raises(HubbleCheckValidationError) as exception:
            stat.validate_params(check_id, block_dict, {})
            pytest.fail("Check should not have passed")

    def test_valid_params1(self):
        """
        valid param, should pass
        """
        block_dict={"args": {"path": "test"}}
        check_id = "test-1"

        stat.validate_params(check_id, block_dict, {})

    def test_filtered_logs1(self):
        """
        valid param, should pass
        """
        block_dict={"args": {"path": "test234"}}
        check_id = "test-1"

        res = stat.get_filtered_params_to_log(check_id, block_dict, {})
        self.assertEqual(res, {"path": "test234"})

    @patch("os.path.isfile")
    def test_execute1(self, isfile_mock):
        """
        File exists, run module. Should pass
        """
        def _stats(path):
            return {"uid": 1, "gid": 2}
        
        isfile_mock.return_value = True
        stat.__salt__ = {
            "file.stats": _stats
        }
        block_dict={"args": {"path": "randompath"}}
        check_id = "test-1"

        status, res = stat.execute(check_id, block_dict, {})
        self.assertEqual(res, {"result": {"uid": 1, "gid": 2}})

    @patch("os.path.isfile")
    def test_execute2(self, isfile_mock):
        """
        File doesnt exist. Should fail
        """
        def _stats(path):
            return {"uid": 1, "gid": 2}
        
        isfile_mock.return_value = False
        stat.__salt__ = {
            "file.stats": _stats
        }
        block_dict={"args": {"path": "randompath"}}
        check_id = "test-1"

        status, res = stat.execute(check_id, block_dict, {})
        self.assertFalse(status)
        self.assertEqual(res, {"error": "file_not_found"})
