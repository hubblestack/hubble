from unittest import TestCase
from unittest.mock import patch
import pytest

from hubblestack.extmods.hubble_mods import time_sync
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestTimeSync(TestCase):
    """
    Unit tests for time_sync module
    """
    def test_invalid_params1(self):
        """
        No mandatory param is passed
        should fail
        """
        block_dict={}
        check_id = "test-1"

        with pytest.raises(HubbleCheckValidationError) as exception:
            time_sync.validate_params(check_id, block_dict)
            pytest.fail("Check should not have passed")

    def test_valid_params1(self):
        """
        valid param, should pass
        """
        block_dict={"args": {"ntp_servers": [
            "server1", "server2"
        ]}}
        check_id = "test-1"

        time_sync.validate_params(check_id, block_dict)

    def test_filtered_logs1(self):
        """
        valid param, should pass
        """
        block_dict={"args": {"ntp_servers": [
            "server1", "server2"
        ]}}
        check_id = "test-1"

        res = time_sync.get_filtered_params_to_log(check_id, block_dict)
        self.assertEqual(res, {"ntp_servers": [
            "server1", "server2"]})

    def test_execute1(self):
        """
        Sample execution. Having 5 ntp servers
        """
        block_dict={
            'args': {
                "ntp_servers": [
                    "server1", "server2", "server3", "server4", "server5"
                ]
            }
        }
        check_id = "test-1"
        test_obj = TestClass()

        with patch('hubblestack.extmods.hubble_mods.time_sync.ntplib.NTPClient') as ntplib_mock:
            ntplib_mock.return_value.request.return_value = test_obj

            status, res = time_sync.execute(check_id, block_dict)
            print(res['result'])
            self.assertEqual(status, True)
            self.assertEqual(res['result'], [{'ntp_server': 'server1', 'replied': True, 'offset': 5}, {'ntp_server': 'server2', 'replied': True, 'offset': 5}, {'ntp_server': 'server3', 'replied': True, 'offset': 5}, {'ntp_server': 'server4', 'replied': True, 'offset': 5}, {'ntp_server': 'server5', 'replied': True, 'offset': 5}])

    def test_execute2(self):
        """
        Sample execution. Having 2 ntp servers
        """
        block_dict={
            'args': {
                "ntp_servers": [
                    "server1", "server2"
                ]
            }
        }
        check_id = "test-1"
        test_obj = TestClass()

        with patch('hubblestack.extmods.hubble_mods.time_sync.ntplib.NTPClient') as ntplib_mock:
            ntplib_mock.return_value.request.return_value = test_obj

            status, res = time_sync.execute(check_id, block_dict)
            self.assertEqual(status, True)
            self.assertEqual(res['result'], [{'ntp_server': 'server1', 'replied': True, 'offset': 5}, {'ntp_server': 'server2', 'replied': True, 'offset': 5}])

class TestClass:
    """A test class"""
    offset = 5
