from unittest import TestCase
import pytest
from unittest.mock import patch
import mock

from hubblestack.extmods.hubble_mods import win_pkg
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestWinPkg(TestCase):

    @patch('hubblestack.extmods.module_runner.runner_utils.get_param_for_module')
    def test_get_filtered_params_to_log(self, get_param_for_module_mock):
        """
        Check filtered logs output
        """
        pkg_name = "Local Administrator Password Solution"
        block_id = "test_get_filtered_params_to_log"
        block_dict = {
                        "args" :
                            {
                                "name": pkg_name
                            }
                     }
        get_param_for_module_mock.return_value = pkg_name
        result = win_pkg.get_filtered_params_to_log(block_id, block_dict, extra_args=None)
        self.assertEquals(result.get("name"), pkg_name)

    @patch('hubblestack.extmods.module_runner.runner_utils.get_param_for_module')
    def test_validate_params_positive(self, get_param_for_module_mock):
        """
        test validate params for positive result
        """
        pkg_name = "Local Administrator Password Solution"
        block_id = "test_validate_params_positive"
        block_dict = {
                        "args" :
                            {
                                "name" : pkg_name
                            }
                     }

        win_pkg.runner_utils.get_chained_param = mock.Mock(return_value=None)
        get_param_for_module_mock.return_value = pkg_name
        win_pkg.validate_params(block_id, block_dict)

    @patch('hubblestack.extmods.module_runner.runner_utils.get_param_for_module')
    def test_validate_params_negative(self, get_param_for_module_mock):
        """
        Test whether invalid input params will raise an exception or not.
        """
        pkg_name = None
        block_id = "test_validate_params_negative"
        block_dict = {
            "args":
                {
                    "name": pkg_name
                }
        }

        win_pkg.runner_utils.get_chained_param = mock.Mock(return_value=None)
        get_param_for_module_mock.return_value = pkg_name

        with pytest.raises(HubbleCheckValidationError) as exception:
            win_pkg.validate_params(block_id, block_dict)
            pytest.fail('Should not have passed')
        self.assertTrue('Mandatory parameter: name not found' in str(exception.value))

    @patch('hubblestack.extmods.module_runner.runner_utils.get_param_for_module')
    def test_execute_positive(self, get_param_for_module_mock):
        """
        test the execute function with positive result
        """
        __salt__ = {}
        pkg_list = {"Local Administrator Password Solution": "6.2.0.0"}
        pkg_name = "Local Administrator Password Solution"
        block_id = "test_validate_params_negative"
        block_dict = {
            "args":
                {
                    "name": pkg_name
                }
        }

        def list_pkgs():
            return pkg_list

        __salt__['pkg.list_pkgs'] = list_pkgs
        win_pkg.__salt__ = __salt__
        win_pkg.runner_utils.get_chained_param = mock.Mock(return_value=None)
        get_param_for_module_mock.return_value = pkg_name

        result = win_pkg.execute(block_id, block_dict)
        self.assertTrue(result[0])
        self.assertTrue(isinstance(result[1], dict))
        self.assertEquals(pkg_list.get("Local Administrator Password Solution"), result[1].get("result").get("package_version"))