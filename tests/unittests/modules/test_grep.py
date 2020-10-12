from unittest import TestCase
from unittest.mock import patch
import pytest

from hubblestack.extmods.hubble_mods import grep
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestGrep(TestCase):
    """
    Unit tests for grep module
    """

    def testValidateParams1(self):
        """
        Mandatory param passed. Test should pass
        """
        block_id = "test-1"
        block_dict = {'args':
            {
                'path': 'dummy file',
                'pattern': 'test pattern'
            }
        }
        grep.validate_params(block_id, block_dict, {})

    def testValidateParams2(self):
        """
        Mandatory param path not passed. Test should raise HubbleCheckValidationError
        """
        block_id = "test-2"
        block_dict = {'args':
            {
                'pattern': 'test pattern'
            }
        }

        with pytest.raises(HubbleCheckValidationError) as exception:
            grep.validate_params(block_id, block_dict, {})
            pytest.fail('Should not have passed')
        self.assertTrue('Mandatory parameter: path not found' in str(exception.value))

    def testFilteredLogs1(self):
        """
        Check filtered logs output
        """
        block_id = "test-3"
        block_dict = {'args':
            {
                'path': 'test-file',
                'pattern': 'test pattern',
                'grep_args': '-E'
            }
        }
        expected_dict = {'path': 'test-file',
                         'pattern': 'test pattern'}
        result = grep.get_filtered_params_to_log(block_id, block_dict)
        self.assertDictEqual(expected_dict, result)

    @patch('os.path.isfile')
    def testExecute1(self, mockOS):
        """
        Check execute when file provided is not present
        Test should return status as False and error dict as output
        """
        block_id = "test-4"
        block_dict = {'args':
            {
                'path': 'test-file',
                'pattern': 'test pattern'
            }
        }
        expected_dict = {'error': 'file_not_found'}
        mockOS.return_value = False
        status, result_dict = grep.execute(block_id, block_dict, {})
        self.assertFalse(status)
        self.assertDictEqual(expected_dict, result_dict)

    @patch('os.path.isfile')
    @patch('hubblestack.extmods.hubble_mods.grep._grep')
    def testExecute2(self, mockGrep, mockOS):
        """
        Check execute when file provided is present
        Test should return status as True and result dict as output
        """
        text = "abcd test abcd"
        block_id = "test-5"
        block_dict = {'args':
            {
                'path': 'test-file',
                'pattern': 'test'
            }
        }
        mockGrep.return_value = {"stdout": text, "retcode": 0}
        mockOS.return_value = True

        expected_dict={'result': text}
        status, result_dict = grep.execute(block_id, block_dict, {})
        self.assertTrue(status)
        self.assertDictEqual(expected_dict, result_dict)

    @patch('os.path.expanduser')
    def testGrep1(self, mockOS):
        """
        Check grep function. Validate the output of grep command
        """
        text = "dummy test"
        path = 'test-file'
        pattern = 'test'

        def mock_grep(cmd, python_shell, ignore_retcode, stdin):
            return {"stdout": text}
        mockOS.return_value = path
        __salt__ = {}
        __salt__['cmd.run_all'] = mock_grep

        grep.__salt__ = __salt__
        expected_dict = {'stdout': text}
        result = grep._grep(path, None, pattern)
        self.assertDictEqual(expected_dict, result)