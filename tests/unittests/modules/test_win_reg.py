from unittest import TestCase
from unittest.mock import patch
import pytest
import mock

from hubblestack.extmods.hubble_mods import win_reg
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestWinReg(TestCase):

    @patch('hubblestack.extmods.module_runner.runner_utils.get_param_for_module')
    def test_get_filtered_params_to_log(self, get_param_for_module_mock):
        """
        Check filtered logs output
        """
        reg_name = "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application\\MaxSize"
        block_id = "test_get_filtered_params_to_log"
        block_dict = {
                        "args" :
                            {
                                "name": reg_name
                            }
                     }
        get_param_for_module_mock.return_value = reg_name
        result = win_reg.get_filtered_params_to_log(block_id, block_dict, extra_args=None)
        self.assertEqual(result.get("name"), reg_name)

    def test_reg_path_splitter(self):
        """
        Check reg_path_splitter function
        """
        reg_name = "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application\\MaxSize"
        result = win_reg._reg_path_splitter(reg_name)
        self.assertEqual(result.get("value"), "MaxSize")
        self.assertEqual(result.get("hive"), "HKEY_LOCAL_MACHINE")
        self.assertEqual(result.get("key"), "Software\\Policies\\Microsoft\\Windows\\EventLog\\Application")

    @patch('hubblestack.extmods.module_runner.runner_utils.get_param_for_module')
    def test_validate_params_positive(self, get_param_for_module_mock):
        """
        test validate params for positive result
        """
        reg_name = "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application\\MaxSize"
        block_id = "test_validate_params_positive"
        block_dict = {
                        "args" :
                            {
                                "name" : reg_name
                            }
                     }

        win_reg.runner_utils.get_chained_param = mock.Mock(return_value=None)
        get_param_for_module_mock.return_value = reg_name
        win_reg.validate_params(block_id, block_dict)

    @patch('hubblestack.extmods.module_runner.runner_utils.get_param_for_module')
    def test_validate_params_negative(self, get_param_for_module_mock):
        """
        Test whether invalid input params will raise an exception or not.
        """
        reg_name = None
        block_id = "test_validate_params_negative"
        block_dict = {
            "args":
                {
                    "name": reg_name
                }
        }

        win_reg.runner_utils.get_chained_param = mock.Mock(return_value=None)
        get_param_for_module_mock.return_value = reg_name

        with pytest.raises(HubbleCheckValidationError) as exception:
            win_reg.validate_params(block_id, block_dict, {})
            pytest.fail('Should not have passed')
        self.assertTrue('Mandatory parameter: name not found' in str(exception.value))

    def test_read_reg_value_positive(self):
        """
        Check if the registry has an actual value set
        """
        __salt__ = {}
        mocked_object = {"success": "True", "vdata": 0}

        def read_value(hive="HKLM",
                       key=r"SYSTEM\CurrentControlSet\Control\ProductOptions",
                       vname="ProductType"):
            return mocked_object
        __salt__['reg.read_value'] = read_value

        win_reg.__salt__ = __salt__

        reg_value = "MaxSize"
        reg_hive = "HKEY_LOCAL_MACHINE"
        reg_key = "Software\\Policies\\Microsoft\\Windows\\EventLog\\Application"
        result = win_reg._read_reg_value(reg_hive, reg_key, reg_value)
        self.assertEqual(result, 0)

    def test_read_reg_value_negative_value_not_set(self):
        """
        Check if the registry has '(value not set)'
        """
        __salt__ = {}
        mocked_object = {"success": "True", "vdata": '(value not set)'}

        def read_value(hive="HKLM",
                       key=r"SYSTEM\CurrentControlSet\Control\ProductOptions",
                       vname="ProductType"):
            return mocked_object

        __salt__['reg.read_value'] = read_value

        win_reg.__salt__ = __salt__

        reg_value = "MaxSize"
        reg_hive = "HKEY_LOCAL_MACHINE"
        reg_key = "Software\\Policies\\Microsoft\\Windows\\EventLog\\Application"
        result = win_reg._read_reg_value(reg_hive, reg_key, reg_value)
        self.assertFalse(result)

    def test_read_reg_value_negative_no_success(self):
        """
        success not returned when fetching value from registry
        """
        __salt__ = {}
        mocked_object = {}

        def read_value(hive="HKLM",
                       key=r"SYSTEM\CurrentControlSet\Control\ProductOptions",
                       vname="ProductType"):
            return mocked_object

        __salt__['reg.read_value'] = read_value

        win_reg.__salt__ = __salt__

        reg_value = "MaxSize"
        reg_hive = "HKEY_LOCAL_MACHINE"
        reg_key = "Software\\Policies\\Microsoft\\Windows\\EventLog\\Application"
        result = win_reg._read_reg_value(reg_hive, reg_key, reg_value)
        self.assertFalse(result)

    def test_find_option_value_in_reg_positice_hku(self):
        """
        Check if the registry has an actual value set when hive is hku
        """
        __salt__ = {}
        mocked_result = 0

        registry_list = "HKEY_USERS\\S-1-5-21-1645406227-2048958880-3100449314-1008"

        def cmd_run(cmd):
            return registry_list

        __salt__['cmd.run'] = cmd_run
        win_reg._read_reg_value = mock.Mock(return_value=mocked_result)
        win_reg.__salt__ = __salt__

        reg_value = "MaxSize"
        reg_hive = "hku"
        reg_key = "Software\\Policies\\Microsoft\\Windows\\EventLog\\Application"
        result = win_reg._find_option_value_in_reg(reg_hive, reg_key, reg_value)
        self.assertEqual(result.get("S-1-5-21-1645406227-2048958880-3100449314-1008"), 0)

    def test_find_option_value_in_reg_negative_hku(self):
        """
        Check if the function returns empty dict when _Classes is present in reg name
        """
        __salt__ = {}
        mocked_result = 0

        registry_list = "HKEY_USERS\\S-1-5-21-1645406227-2048958880-3100449314-1008_Classes"

        def cmd_run(cmd):
            return registry_list

        __salt__['cmd.run'] = cmd_run
        win_reg._read_reg_value = mock.Mock(return_value=mocked_result)
        win_reg.__salt__ = __salt__

        reg_value = "MaxSize"
        reg_hive = "hku"
        reg_key = "Software\\Policies\\Microsoft\\Windows\\EventLog\\Application"
        result = win_reg._find_option_value_in_reg(reg_hive, reg_key, reg_value)
        self.assertEqual(result, {})

    @patch('hubblestack.extmods.hubble_mods.win_reg._reg_path_splitter')
    @patch('hubblestack.extmods.hubble_mods.win_reg._find_option_value_in_reg')
    @patch('hubblestack.extmods.module_runner.runner_utils.get_param_for_module')
    def test_execute_positive(self, get_param_for_module_mock, _find_option_value_in_reg_mock, _reg_path_splitter_mock):
        """
        test the execute function with positive result
        """
        reg_name = "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application\\MaxSize"
        reg_hive = "HKEY_LOCAL_MACHINE"
        reg_key = "Software\\Policies\\Microsoft\\Windows\\EventLog\\Application"
        reg_value = "MaxSize"
        reg_dict = {"hive": reg_hive, "key" : reg_key, "value": reg_value}
        block_id = "test_execute"
        block_dict = {
                        "args" :
                            {
                                "name" : reg_name
                            }
                     }

        _reg_path_splitter_mock.return_value = reg_dict
        _find_option_value_in_reg_mock.return_value = '0'
        get_param_for_module_mock.return_value = reg_name
        result = win_reg.execute(block_id, block_dict)
        self.assertTrue(result[0])
        self.assertEqual(len(result), 2)
        result_dict = result[1]
        self.assertTrue('result' in result_dict)
        self.assertEqual(result_dict.get("result").get(reg_name), '0')

    @patch('hubblestack.extmods.hubble_mods.win_reg._reg_path_splitter')
    @patch('hubblestack.extmods.hubble_mods.win_reg._find_option_value_in_reg')
    @patch('hubblestack.extmods.module_runner.runner_utils.get_param_for_module')
    def test_execute_negative(self, get_param_for_module_mock, _find_option_value_in_reg_mock, _reg_path_splitter_mock):
        """
        test the execute function with positive result
        """
        reg_name = "invalidRegistryName"
        reg_hive = "HKEY_LOCAL_MACHINE"
        reg_key = "Software\\Policies\\Microsoft\\Windows\\EventLog\\Application"
        reg_value = "MaxSize"
        reg_dict = {"hive": reg_hive, "key" : reg_key, "value": reg_value}
        block_id = "test_execute"
        block_dict = {
                        "args" :
                            {
                                "name" : reg_name
                            }
                     }

        _reg_path_splitter_mock.return_value = reg_dict
        _find_option_value_in_reg_mock.return_value = False
        get_param_for_module_mock.return_value = reg_name
        result = win_reg.execute(block_id, block_dict)
        self.assertFalse(result[0])
