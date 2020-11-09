from unittest import TestCase
from unittest.mock import patch
import pytest


from hubblestack.extmods.hubble_mods import curl
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestCurl(TestCase):
    """
    Unit tests for curl module
    """
    def test_invalid_params1(self):
        """
        No mandatory param is passed
        should fail
        """
        block_dict={"args": {
            "function": "invalid"
        }}
        check_id = "test-1"

        with pytest.raises(HubbleCheckValidationError) as exception:
            curl.validate_params(check_id, block_dict, {})
            pytest.fail("Check should not have passed")

    def test_valid_params1(self):
        """
        valid param, should pass
        """
        block_dict={"args": {"function": "GET", "url": "test-xyz"}}
        check_id = "test-1"

        curl.validate_params(check_id, block_dict, {})

    def test_valid_params2(self):
        """
        valid param, default function name from module, should pass
        """
        block_dict={"args": {"url": "test-xyz"}}
        check_id = "test-1"

        curl.validate_params(check_id, block_dict, {})

    def test_filtered_logs1(self):
        """
        valid param, should pass
        """
        block_dict={"args": {"function": "GET", "url": "test"}}
        check_id = "test-1"

        res = curl.get_filtered_params_to_log(check_id, block_dict, {})
        self.assertEqual(res, {"url": "test"})

    def test_execute_get(self):
        """
        test a get request
        """
        class ResultMock:
            def __init__(self, status_code):
                self.status_code = status_code
            def json(self):
                return {"id": 1, "name": "test"}
            def raise_for_status(self):
                pass
        block_dict={"args": {"function": "GET", "url": "test"}}
        result_mock = ResultMock(200)
        expected_result = {'status': 200, 'response': {'id': 1, 'name': 'test'}}
        with patch('hubblestack.extmods.hubble_mods.curl.requests') as requests_mock:
            requests_mock.get.return_value = result_mock
            status, res = curl.execute('test', block_dict, {})
            self.assertEqual(res['result'], expected_result)

    def test_execute_post(self):
        """
        test a post request
        """
        class ResultMock:
            def __init__(self, status_code):
                self.status_code = status_code
            def json(self):
                return {"id": 1, "name": "test"}
            def raise_for_status(self):
                pass
        block_dict={"args": {"function": "POST", "url": "test"}}
        result_mock = ResultMock(200)
        expected_result = {'status': 200, 'response': {'id': 1, 'name': 'test'}}
        with patch('hubblestack.extmods.hubble_mods.curl.requests') as requests_mock:
            requests_mock.post.return_value = result_mock
            status, res = curl.execute('test', block_dict, {})
            self.assertEqual(res['result'], expected_result)

    def test_execute_put(self):
        """
        test a post request
        """
        class ResultMock:
            def __init__(self, status_code):
                self.status_code = status_code
            def json(self):
                return {"id": 1, "name": "test"}
            def raise_for_status(self):
                pass
        block_dict={"args": {"function": "PUT", "url": "test"}}
        result_mock = ResultMock(200)
        expected_result = {'status': 200, 'response': {'id': 1, 'name': 'test'}}
        with patch('hubblestack.extmods.hubble_mods.curl.requests') as requests_mock:
            requests_mock.put.return_value = result_mock
            status, res = curl.execute('test', block_dict, {})
            self.assertEqual(res['result'], expected_result)