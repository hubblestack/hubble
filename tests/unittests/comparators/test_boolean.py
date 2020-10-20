from unittest import TestCase
from unittest.mock import patch
import pytest

from hubblestack.extmods.comparators import boolean as boolean_comparator


class TestBooleanMatch(TestCase):
    """
    Unit tests for Boolean::match comparator
    """

    def test_match1(self):
        """
        Match True. Positive test
        """
        result_to_compare = True
        args = {
            "type": "boolean",
            "match": True
        }
        status, result = boolean_comparator.match("test-1", result_to_compare, args)
        self.assertTrue(status)

    def test_match2(self):
        """
        Match False. Positive test
        """
        result_to_compare = True
        args = {
            "type": "boolean",
            "match": False
        }
        status, result = boolean_comparator.match("test-1", result_to_compare, args)
        self.assertFalse(status)

    def test_match3(self):
        """
        Match string against Boolean by boolean_cast
        """
        result_to_compare = "a test string"
        args = {
            "type": "boolean",
            "match": True,
            "boolean_cast": True
        }
        status, result = boolean_comparator.match("test-1", result_to_compare, args)
        self.assertTrue(status)

    def test_match4(self):
        """
        Match string against Boolean, boolean_cast=False. Should fail
        """
        result_to_compare = "a test string"
        args = {
            "type": "boolean",
            "match": True,
            "boolean_cast": False
        }
        status, result = boolean_comparator.match("test-1", result_to_compare, args)
        self.assertFalse(status)
