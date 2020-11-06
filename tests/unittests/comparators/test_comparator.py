from unittest import TestCase
import pytest

from hubblestack.utils.hubble_error import HubbleCheckFailedError
import hubblestack.extmods.module_runner.comparator as comparator

class TestComparatorMatch(TestCase):
    """
    Unit tests for dict::match comparator
    """
    def test_match1(self):
        """
        Module failed with valid error. Comparator is configured to return success
        """
        args = {
            'success_on_error': ['file_not_found']
        }
        module_result = {'error': 'file_not_found'}
        module_status = False
        status, result = comparator.run('test', args, module_result, module_status)
        self.assertTrue(status)

    def test_match2(self):
        """
        Module failed with valid error. Comparator is NOT configured to return success
        """
        args = {
            'success_on_error': ['file_not_found']
        }
        module_result = {'error': 'unknown_error'}
        module_status = False
        status, result = comparator.run('test', args, module_result, module_status)
        self.assertFalse(status)

    def test_match3(self):
        """
        Module failed with valid error. Comparator is NOT configured to return success
        """
        args = {}
        module_result = {'error': 'unknown_error'}
        module_status = False
        status, result = comparator.run('test', args, module_result, module_status)
        self.assertFalse(status)

    def test_match4(self):
        """
        Module passed. Send to valid comparator. Should pass
        """
        def test_func(a, b, c):
            return True, ''
        comparator_dict = {
            "dict.match": test_func
        }
        comparator.__comparator__ = comparator_dict

        args = {
            "type": "dict",
            "match": {
                "uid": 0,
                "gid": 0
            }
        }
        module_result = {
            "uid": 0,
            "gid": 0,
        }
        module_status = True
        status, result = comparator.run('test', args, module_result, module_status)
        self.assertTrue(status)

    def test_match5(self):
        """
        Module passed. Send to INVALID comparator. Should fail
        """
        def test_func(a, b, c):
            return True, ''
        comparator_dict = {
            "dict.match": test_func
        }
        comparator.__comparator__ = comparator_dict

        args = {
            "type": "dict",
            "unknown_command": {
                "uid": 0,
                "gid": 0
            }
        }
        module_result = {
            "uid": 0,
            "gid": 0,
        }
        module_status = True

        with pytest.raises(HubbleCheckFailedError) as exception:
            status, result = comparator.run('test', args, module_result, module_status)
            pytest.fail('Should not have come here')
