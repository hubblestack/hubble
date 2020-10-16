from unittest import TestCase
from unittest.mock import patch
import pytest

from hubblestack.extmods.hubble_mods import osquery
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestOsquery(TestCase):
    """
    Unit tests for osquery module
    """

    def test_validate_params1(self):
        """
        No mandatory param passed.
        Test should fail
        """
        block_dict = {}
        check_id = "test-1"

        with pytest.raises(HubbleCheckValidationError) as exception:
            osquery.validate_params(check_id, block_dict, {})
            pytest.fail("Check should not have passed")

    def test_valid_params2(self):
        """
        valid param, should pass
        """
        block_dict = {"args": {"query": "sample query"}}
        check_id = "test-2"

        osquery.validate_params(check_id, block_dict, {})

    def test_filtered_logs1(self):
        """
        valid param, should pass
        """
        block_dict = {"args": {"query": "sample query"}}
        check_id = "test-3"

        res = osquery.get_filtered_params_to_log(check_id, block_dict, {})
        self.assertEqual(res, {"query": "sample query"})

    @patch("os.path.isfile")
    def test_execute1(self, isfile_mock):
        """
        positive case. Test should pass
        :return:
        """

        def _mock_osquery(cmd, timeout, python_shell):
            return {'pid': 1,
                    'retcode': 0,
                    'stdout': '[\n{"count": 1}\n]',
                    'stderr': ''}

        isfile_mock.return_value = True
        osquery.__grains__ = {
            'osquerybinpath': 'dummy path'
        }
        osquery.__salt__ = {
            'cmd.run_all': _mock_osquery
        }
        block_dict = {"args": {"query": "sample query"}}
        check_id = "test-4"
        status, res = osquery.execute(check_id, block_dict, {})
        self.assertTrue(status)
        self.assertEqual(res, {'result': [{'count': 1}]})

    @patch("os.path.isfile")
    def test_execute2(self, isfile_mock):
        """
        positive case with cast_to_string set to true.
        Test should pass
        """

        def _mock_osquery(cmd, timeout, python_shell):
            return {'pid': 1,
                    'retcode': 0,
                    'stdout': '[\n{"count": 1}\n]',
                    'stderr': ''}

        isfile_mock.return_value = True
        osquery.__grains__ = {
            'osquerybinpath': 'dummy path'
        }
        osquery.__salt__ = {
            'cmd.run_all': _mock_osquery
        }
        block_dict = {"args": {"query": "sample query",
                               "cast_to_string": True}}
        check_id = "test-5"
        status, res = osquery.execute(check_id, block_dict, {})
        self.assertTrue(status)
        self.assertEqual(res, {'result': [{'count': '1'}]})

    def test_execute3(self):
        """
        negative case. Osquery binary not found
        Test should fail
        """

        def _mock_osquery(cmd, timeout, python_shell):
            return {'pid': 1,
                    'retcode': 0,
                    'stdout': '[\n{"count": 1}\n]',
                    'stderr': ''}

        osquery.__grains__ = {
            'osquerybinpath': 'dummy path'
        }
        osquery.__salt__ = {
            'cmd.run_all': _mock_osquery
        }
        block_dict = {"args": {"query": "sample query"}}
        check_id = "test-6"
        status, res = osquery.execute(check_id, block_dict, {})
        self.assertFalse(status)

    def test_execute4(self):
        """
        negative case. curl command set in osquery
        Test should fail
        """

        def _mock_osquery(cmd, timeout, python_shell):
            return {'pid': 1,
                    'retcode': 0,
                    'stdout': '[\n{"count": 1}\n]',
                    'stderr': ''}

        osquery.__grains__ = {
            'osquerybinpath': 'dummy path'
        }
        osquery.__salt__ = {
            'cmd.run_all': _mock_osquery
        }
        block_dict = {"args": {"query": "curl query"}}
        check_id = "test-7"
        status, res = osquery.execute(check_id, block_dict, {})
        self.assertFalse(status)

    def test_execute5(self):
        """
        negative case. custom osquery path sent
        Test should fail
        """

        def _mock_osquery(cmd, timeout, python_shell):
            return {'pid': 1,
                    'retcode': 0,
                    'stdout': '[\n{"count": 1}\n]',
                    'stderr': ''}

        osquery.__grains__ = {
            'osquerybinpath': 'dummy path'
        }
        osquery.__salt__ = {
            'cmd.run_all': _mock_osquery
        }
        block_dict = {"args": {"query": "sample query",
                               "osquery_path": "sample path"}}
        check_id = "test-8"
        status, res = osquery.execute(check_id, block_dict, {})
        self.assertFalse(status)
