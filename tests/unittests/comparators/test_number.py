from unittest import TestCase
import pytest

from hubblestack.extmods.comparators import number as number_comparator
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestNumberMatch(TestCase):
    """
    Unit tests for number::match comparator
    """

    def test_match1(self):
        """
        Match simple number. Positive test
        """
        result_to_compare = 10
        args = {
            "type": "number",
            "match": 10
        }
        status, result = number_comparator.match("test-1", result_to_compare, args)
        self.assertTrue(status)

    def test_match2(self):
        """
        Match simple number. Match with operator
        """
        result_to_compare = 10
        args = {"type": "number", "match": "> 5"}
        status, result = number_comparator.match("test-1", result_to_compare, args)
        self.assertTrue(status)

        result_to_compare = 20
        args = {"type": "number", "match": ">=10"}
        status, result = number_comparator.match("test-1", result_to_compare, args)
        self.assertTrue(status)

        result_to_compare = 20
        args = {"type": "number", "match": "<10"}
        status, result = number_comparator.match("test-1", result_to_compare, args)
        self.assertFalse(status)

        result_to_compare = 20
        args = {"type": "number", "match": "<= 40"}
        status, result = number_comparator.match("test-1", result_to_compare, args)
        self.assertTrue(status)

        result_to_compare = 20
        args = {"type": "number", "match": "==20"}
        status, result = number_comparator.match("test-1", result_to_compare, args)
        self.assertTrue(status)

        result_to_compare = 20
        args = {"type": "number", "match": "!= 20"}
        status, result = number_comparator.match("test-1", result_to_compare, args)
        self.assertFalse(status)

    def test_match3(self):
        """
        Invalid operator. Should raise exception
        """
        result_to_compare = 10
        args = {
            "type": "number",
            "match": "^ 10"
        }

        with pytest.raises(HubbleCheckValidationError) as exception:
            status, result = number_comparator.match("test-1", result_to_compare, args)
            pytest.fail("Check should not have passed")


class TestNumberMatchAny(TestCase):
    """
    Unit tests for number::match_any comparator
    """

    def test_match1(self):
        """
        Match simple number. Positive test
        """
        result_to_compare = 10
        args = {
            "type": "number",
            "match_any": [10, 20, 30]
        }
        status, result = number_comparator.match_any("test-1", result_to_compare, args)
        self.assertTrue(status)

    def test_match2(self):
        """
        Test with operators in list
        """
        result_to_compare = 10
        args = {"type": "number", "match_any": [10, 20, 30]}
        status, result = number_comparator.match_any("test-1", result_to_compare, args)
        self.assertTrue(status)

        result_to_compare = 10
        args = {"type": "number", "match_any": [20, ">= 10", 30]}
        status, result = number_comparator.match_any("test-1", result_to_compare, args)
        self.assertTrue(status)

        result_to_compare = 10
        args = {"type": "number", "match_any": ["<1", 20, 30]}
        status, result = number_comparator.match_any("test-1", result_to_compare, args)
        self.assertFalse(status)
