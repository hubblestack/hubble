from unittest import TestCase

from hubblestack.extmods.comparators import string as string_comparator


class TestStringMatch(TestCase):
    """
    Unit tests for String::match comparator
    """

    def test_match1(self):
        """
        Match simple string. Positive test
        """
        result_to_compare = "root"
        args = {
            "type": "string",
            "match": "root"
        }
        status, result = string_comparator.match("test-1", result_to_compare, args)
        self.assertTrue(status)

    def test_match2(self):
        """
        Match simple string. Negative test
        """
        result_to_compare = "shadow"
        args = {
            "type": "string",
            "match": "root"
        }
        status, result = string_comparator.match("test-2", result_to_compare, args)
        self.assertFalse(status)

    def test_match4(self):
        """
        Match simple string. Case insensitive match. Must fail
        """
        result_to_compare = "RooT1"
        args = {
            "type": "string",
            "match": "root",
            "case_sensitive": False
        }
        status, result = string_comparator.match("test-2", result_to_compare, args)
        self.assertFalse(status)

    def test_match6(self):
        """
        Match simple string. exact_match=false. Must fail
        """
        result_to_compare = "roots"
        args = {
            "type": "string",
            "match": "root",
            "exact_match": True
        }
        status, result = string_comparator.match("test-2", result_to_compare, args)
        self.assertFalse(status)

    def test_match7(self):
        """
        Match simple string. is_regex=true. Must pass
        """
        result_to_compare = "roots"
        args = {
            "type": "string",
            "match": "^r",
            "is_regex": True
        }
        status, result = string_comparator.match("test-2", result_to_compare, args)
        self.assertTrue(status)

    def test_match8(self):
        """
        Match simple string. is_regex=true. Must fail
        """
        result_to_compare = "root"
        args = {
            "type": "string",
            "match": "^t",
            "is_regex": True
        }
        status, result = string_comparator.match("test-2", result_to_compare, args)
        self.assertFalse(status)


class TestStringMatchAny(TestCase):
    """
    Unit tests for String::match_any comparator
    """

    def test_match_any1(self):
        """
        Match list of strings. Positive test
        """
        result_to_compare = "root"
        args = {
            "type": "string",
            "match_any": {
                "root",
                "shadow"
            }
        }
        status, result = string_comparator.match_any("test-1", result_to_compare, args)
        self.assertTrue(status)

    def test_match_any2(self):
        """
        Match list of strings. must fail
        """
        result_to_compare = "root"
        args = {
            "type": "string",
            "match_any": {
                "toor",
                "shadow"
            }
        }
        status, result = string_comparator.match_any("test-1", result_to_compare, args)
        self.assertFalse(status)

    def test_match_any3(self):
        """
        Match list of strings. must pass with regex
        """
        result_to_compare = "root"
        args = {
            "type": "string",
            "match_any": {
                "toor",
                "shadow",
                "^r"
            },
            "is_regex": True
        }
        status, result = string_comparator.match_any("test-1", result_to_compare, args)
        self.assertTrue(status)
