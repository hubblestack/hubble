from unittest import TestCase
import pytest
import mock

from hubblestack.extmods.hubble_mods import win_reg
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestWinReg(TestCase):

    def test_get_filtered_params_to_log(self):
        """
        Check filtered logs output
        """
        reg_name = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize"
        block_id = "test_get_filtered_params_to_log"
        block_dict = {
                        "args" :
                            {
                                "name": reg_name
                            }
                     }
        win_reg.runner_utils.get_param_for_module = mock.Mock(return_value=reg_name)
        result = win_reg.get_filtered_params_to_log(block_id, block_dict, extra_args=None)
        self.assertEquals(result.get("name"), reg_name)

    def test_reg_path_splitter(self):
        """
        Check reg_path_splitter function
        """
        reg_name = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize"
        result = win_reg._reg_path_splitter(reg_name)
        self.assertEquals(result.get("value"), "MaxSize")
        self.assertEquals(result.get("hive"), "HKEY_LOCAL_MACHINE")
        self.assertEquals(result.get("key"), "Software\\Policies\\Microsoft\\Windows\\EventLog\\Application")

    def test_validate_params_positive(self):
        """
        test validate params for positive result
        """
        reg_name = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize"
        block_id = "test_validate_params_positive"
        block_dict = {
                        "args" :
                            {
                                "name" : reg_name
                            }
                     }

        win_reg.runner_utils.get_chained_param = mock.Mock(return_value=None)
        win_reg.runner_utils.get_param_for_module = mock.Mock(return_value=reg_name)
        win_reg.validate_params(block_id, block_dict)

    def test_validate_params_negative(self):
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
        win_reg.runner_utils.get_param_for_module = mock.Mock(return_value=reg_name)

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

        registry_list = "HKEY_USERS\S-1-5-21-1645406227-2048958880-3100449314-1008"

        def cmd_run(cmd):
            return registry_list

        __salt__['cmd.run'] = cmd_run
        win_reg._read_reg_value = mock.Mock(return_value=mocked_result)
        win_reg.__salt__ = __salt__

        reg_value = "MaxSize"
        reg_hive = "hku"
        reg_key = "Software\\Policies\\Microsoft\\Windows\\EventLog\\Application"
        result = win_reg._find_option_value_in_reg(reg_hive, reg_key, reg_value)
        self.assertEquals(result.get("S-1-5-21-1645406227-2048958880-3100449314-1008"), 0)

    def test_find_option_value_in_reg_negative_hku(self):
        """
        Check if the function returns empty dict when _Classes is present in reg name
        """
        __salt__ = {}
        mocked_result = 0

        registry_list = "HKEY_USERS\S-1-5-21-1645406227-2048958880-3100449314-1008_Classes"

        def cmd_run(cmd):
            return registry_list

        __salt__['cmd.run'] = cmd_run
        win_reg._read_reg_value = mock.Mock(return_value=mocked_result)
        win_reg.__salt__ = __salt__

        reg_value = "MaxSize"
        reg_hive = "hku"
        reg_key = "Software\\Policies\\Microsoft\\Windows\\EventLog\\Application"
        result = win_reg._find_option_value_in_reg(reg_hive, reg_key, reg_value)
        self.assertEquals(result, {})


class TestWinRegWithMocks(TestCase):

    """
    because win_reg module functions are mocked here, a new class object needs to be created so that original functions
    do not get mocked in other test cases.
    """
    def test_execute_positive(self):
        """
        test the execute function with positive result
        """
        reg_name = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize"
        reg_hive = "HKEY_LOCAL_MACHINE"
        reg_key = "Software\Policies\Microsoft\Windows\EventLog\Application"
        reg_value = "MaxSize"
        reg_dict = {"hive": reg_hive, "key" : reg_key, "value": reg_value}
        block_id = "test_execute"
        block_dict = {
                        "args" :
                            {
                                "name" : reg_name
                            }
                     }

        win_reg._reg_path_splitter = mock.Mock(return_value=reg_dict)
        win_reg._find_option_value_in_reg = mock.Mock(return_value='0')
        result = win_reg.execute(block_id, block_dict)
        self.assertTrue(result[0])
        self.assertEquals(len(result), 2)
        result_dict = result[1]
        self.assertTrue('result' in result_dict)
        self.assertEquals(result_dict.get("result").get(reg_name), '0')

    def test_execute_negative(self):
        """
        test the execute function with positive result
        """
        reg_name = "invalidRegistryName"
        reg_hive = "HKEY_LOCAL_MACHINE"
        reg_key = "Software\Policies\Microsoft\Windows\EventLog\Application"
        reg_value = "MaxSize"
        reg_dict = {"hive": reg_hive, "key" : reg_key, "value": reg_value}
        block_id = "test_execute"
        block_dict = {
                        "args" :
                            {
                                "name" : reg_name
                            }
                     }

        win_reg._reg_path_splitter = mock.Mock(return_value=reg_dict)
        win_reg._find_option_value_in_reg = mock.Mock(return_value=False)
        result = win_reg.execute(block_id, block_dict)
        self.assertFalse(result[0])
