from unittest import TestCase
import pytest
import mock

from hubblestack.extmods.hubble_mods import win_firewall
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestWinFirewall(TestCase):

    def test_get_filtered_params_to_log(self):
        """
        Check filtered logs output
        """
        setting_name = "Enabled"
        value_type = "Public"
        block_id = "test_get_filtered_params_to_log"
        block_dict = {
                        "args" :
                            {
                                "name": setting_name,
                                "value_type" : value_type
                            }
                     }
        result = win_firewall.get_filtered_params_to_log(block_id, block_dict, extra_args=None)
        self.assertEquals(result.get("name"), setting_name)

    def test_validate_params_positive(self):
        """
        test validate params for positive result
        """
        setting_name = "Enabled"
        value_type = "Public"
        block_id = "test_validate_params_positive"
        block_dict = {
                        "args" :
                            {
                                "name" : setting_name,
                                "value_type": value_type
                            }
                     }

        win_firewall.runner_utils.get_chained_param = mock.Mock(return_value=None)
        win_firewall.validate_params(block_id, block_dict)

    def test_validate_params_negative(self):
        """
        Test whether invalid input params will raise an exception or not.
        """
        block_id = "test_validate_params_negative"
        block_dict = {
            "args":
                {
                    "name": None,
                    "value_type": None
                }
        }

        win_firewall.runner_utils.get_chained_param = mock.Mock(return_value=None)

        with pytest.raises(HubbleCheckValidationError) as exception:
            win_firewall.validate_params(block_id, block_dict)
            pytest.fail('Should not have passed')
        self.assertTrue('Mandatory parameter: name not found' in str(exception.value))

    def test_execute_positive(self):
        """
        test the execute function with positive result
        """
        __firewalldata__ = {"Domain": {"Enabled": "True"}}
        setting_name = "Enabled"
        value_type = "Domain"
        block_id = "test_validate_params_negative"
        block_dict = {
            "args":
                {
                    "name": setting_name,
                    "value_type": value_type
                }
        }

        win_firewall.runner_utils.get_chained_param = mock.Mock(return_value=None)
        win_firewall._import_firewall = mock.Mock(return_value=__firewalldata__)
        result = win_firewall.execute(block_id, block_dict)
        print(result)
        self.assertTrue(result[0])
        self.assertTrue(isinstance(result[1], dict))
        self.assertEquals(result[1].get("result").get("setting_value"), 'true')
