from unittest import TestCase
from unittest.mock import patch
import pytest

from hubblestack.extmods.hubble_mods import bexpr
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestBexpr(TestCase):
    """
    Unit tests for bexpr module
    """

    def testValidateParams1(self):
        """
        Mandatory param passed. Test should pass
        """
        block_id = "test-1"
        block_dict = {'args':
            {
                'expr': 'check1 AND check2',
            }
        }
        extra_args = {
            'caller': 'Audit'
        }
        bexpr.validate_params(block_id, block_dict, extra_args)

    def testValidateParams2(self):
        """
        Mandatory param bexpr not passed. Test should raise HubbleCheckValidationError
        """
        block_id = "test-2"
        block_dict = {'args':
            {
                'expr1': 'check1 AND check2'
            }
        }
        extra_args = {
            'caller': 'Audit'
        }
        with pytest.raises(HubbleCheckValidationError) as exception:
            bexpr.validate_params(block_id, block_dict, extra_args)
            pytest.fail('Should not have passed')
        self.assertTrue('Mandatory parameter: expr not found' in str(exception.value))

    def testFilteredLogs1(self):
        """
        Check filtered logs output
        """
        block_id = "test-3"
        block_dict = {'args':
            {
                'expr': 'check1 OR check2',
            }
        }
        expected_dict = {'expr': 'check1 OR check2'}
        result = bexpr.get_filtered_params_to_log(block_id, block_dict)
        self.assertDictEqual(expected_dict, result)

    def testExecute1(self):
        """
        Run execute when no check is referred in boolean expression
        Test should raise HubbleCheckValidationError
        """
        block_id = "test-4"
        block_dict = {'args':
            {
                'expr': 'OR AND'
            }
        }
        result_list = []
        extra_args = {
            'extra_args': result_list
        }
        with pytest.raises(HubbleCheckValidationError) as exception:
            bexpr.execute(block_id, block_dict, extra_args)
            pytest.fail('Should not have passed')
        self.assertTrue('No checks are referred in the boolean expression' in str(exception.value))

    def testExecute2(self):
        """
        Run execute when no operand is present in boolean expression
        Test should raise HubbleCheckValidationError
        """
        block_id = "test-5"
        block_dict = {'args':
            {
                'expr': 'check1 check2'
            }
        }
        result_list = []
        extra_args = {
            'extra_args': result_list
        }
        with pytest.raises(HubbleCheckValidationError) as exception:
            bexpr.execute(block_id, block_dict, extra_args)
            pytest.fail('Should not have passed')
        self.assertTrue(
            'No operand is present for multiple referred checks in boolean expression' in str(exception.value))

    def testExecute3(self):
        """
        Run execute when referred check is not present in boolean expression
        Test should raise HubbleCheckValidationError
        """
        block_id = "test-6"
        block_dict = {'args':
            {
                'expr': 'check1 AND check2'
            }
        }
        result_list = []
        extra_args = {
            'extra_args': result_list
        }
        with pytest.raises(HubbleCheckValidationError) as exception:
            bexpr.execute(block_id, block_dict, extra_args)
            pytest.fail('Should not have passed')
        self.assertTrue('Please verify correct check is referred' in str(exception.value))

    def testExecute4(self):
        """
        Run execute when referred check evaluated as Error in boolean expression
        Test should raise HubbleCheckValidationError
        """
        block_id = "test-7"
        block_dict = {'args':
            {
                'expr': 'check1 AND check2'
            }
        }
        result_list = [{
            'check_id': 'check1',
            'check_result': 'Success'
        },
            {
                'check_id': 'check2',
                'check_result': 'Error'
            }]
        extra_args = {
            'extra_args': result_list
        }
        with pytest.raises(HubbleCheckValidationError) as exception:
            bexpr.execute(block_id, block_dict, extra_args)
            pytest.fail('Should not have passed')
        self.assertTrue(
            'Referred check: check2 result is Error. Setting boolean expression check result to error' in str(
                exception.value))

    def testExecute5(self):
        """
        Run execute when referred check evaluated as Skipped in boolean expression
        Test should raise HubbleCheckValidationError
        """
        block_id = "test-8"
        block_dict = {'args':
            {
                'expr': 'check1 AND check2'
            }
        }
        result_list = [{
            'check_id': 'check1',
            'check_result': 'Success'
        },
            {
                'check_id': 'check2',
                'check_result': 'Skipped'
            }]
        extra_args = {
            'extra_args': result_list
        }
        with pytest.raises(HubbleCheckValidationError) as exception:
            bexpr.execute(block_id, block_dict, extra_args)
            pytest.fail('Should not have passed')
        self.assertTrue(
            'Referred check: check2 result is Skipped. Setting boolean expression check result to error' in str(
                exception.value))

    def testExecute6(self):
        """
        Run execute when boolean expression evaluated as Success
        Test should return positive result
        """
        block_id = "test-9"
        block_dict = {'args':
            {
                'expr': 'check1 OR check2'
            }
        }
        result_list = [{
            'check_id': 'check1',
            'check_result': 'Success'
        },
            {
                'check_id': 'check2',
                'check_result': 'Failure'
            }]
        extra_args = {
            'extra_args': result_list
        }
        expected_dict = {"result": True}
        status, result_dict = bexpr.execute(block_id, block_dict, extra_args)
        self.assertTrue(status)
        self.assertDictEqual(expected_dict, result_dict)

    def testExecute7(self):
        """
        Run execute when boolean expression evaluated as Failure
        Test should return negative result
        """
        block_id = "test-10"
        block_dict = {'args':
            {
                'expr': 'check1 AND check2'
            }
        }
        result_list = [{
            'check_id': 'check1',
            'check_result': 'Success'
        },
            {
                'check_id': 'check2',
                'check_result': 'Failure'
            }]
        extra_args = {
            'extra_args': result_list
        }
        expected_dict = {"result": False}
        status, result_dict = bexpr.execute(block_id, block_dict, extra_args)
        self.assertTrue(status)
        self.assertDictEqual(expected_dict, result_dict)

    @patch('hubblestack.extmods.hubble_mods.bexpr._evaluate_expression')
    def testExecute8(self, mockBexpr):
        """
        Run execute when boolean expression evaluated throws an Exception
        Test should raise HubbleCheckValidationError
        """
        block_id = "test-11"
        block_dict = {'args':
            {
                'expr': 'check1 AND check2'
            }
        }
        result_list = [{
            'check_id': 'check1',
            'check_result': 'Success'
        },
            {
                'check_id': 'check2',
                'check_result': 'Failure'
            }]
        extra_args = {
            'extra_args': result_list
        }
        mockBexpr.side_effect = Exception("Dummy exception")
        with pytest.raises(HubbleCheckValidationError) as exception:
            bexpr.execute(block_id, block_dict, extra_args)
            pytest.fail('Should not have passed')
        self.assertTrue(
            'Error in evaluating boolean expression:' in str(
                exception.value))
