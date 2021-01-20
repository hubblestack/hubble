from unittest import TestCase
from unittest.mock import patch

from hubblestack.comparators import list as list_comparator


class TestListSize(TestCase):
    """
    Unit tests for list::size comparator
    """

    def test_size1(self):
        """
        Check size of list. Should pass
        """
        result_to_compare = [10, 20, 30]
        args = {
            "type": "list",
            "size": 3
        }
        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (True, "Pass")
            status, result = list_comparator.size("test-1", result_to_compare, args)
            self.assertTrue(status)

    def test_size2(self):
        """
        Check size of list. Should fail
        """
        result_to_compare = [10, 20, 30]
        args = {
            "type": "list",
            "size": 3
        }
        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (False, "Failed")
            status, result = list_comparator.size("test-1", result_to_compare, args)
            self.assertFalse(status)


class TestListMatch(TestCase):
    """
    Unit tests for list::match comparator
    """

    def test_match1(self):
        """
        Positive case. String
        :return:
        """
        result_to_compare = [
            "test-str1",
            "test-str2"
        ]
        args = {
            "type": "list",
            "match": [
                "test-str1",
                "test-str2"
            ]
        }
        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (True, "Pass")
            status, result = list_comparator.match("test-1", result_to_compare, args)
            self.assertTrue(status)
            self.assertEqual(result, "Check Passed")

    def test_match2(self):
        """
        Positive case. Dict
        :return:
        """
        result_to_compare = [
            {"name": "abcd", "status": True, "disabled": False}
        ]
        args = {
            "type": "list",
            "match": [
                {"name": "abcd", "status": True, "disabled": False}
            ]
        }
        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (True, "Pass")
            status, result = list_comparator.match("test-1", result_to_compare, args)
            self.assertTrue(status)
            self.assertEqual(result, "Check Passed")

    def test_match3(self):
        """
        Positive case. With different order of string in lists
        :return:
        """
        result_to_compare = [
            "test-str1",
            "test-str2"
        ]
        args = {
            "type": "list",
            "match": [
                "test-str2",
                "test-str1"
            ]
        }
        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (True, "Pass")
            status, result = list_comparator.match("test-1", result_to_compare, args)
            self.assertTrue(status)
            self.assertEqual(result, "Check Passed")

    def test_match4(self):
        """
        Positive case. With different order of dicts in lists
        :return:
        """
        result_to_compare = [
            {"name": "abcd", "status": True, "disabled": False},
            {"name": "mno", "status": True, "disabled": False}
        ]
        args = {
            "type": "list",
            "match": [
                {"name": "mno", "status": True, "disabled": False},
                {"name": "abcd", "disabled": False, "status": True}
            ]
        }
        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (True, "Pass")
            status, result = list_comparator.match("test-1", result_to_compare, args)
            self.assertTrue(status)
            self.assertEqual(result, "Check Passed")

    def test_match5(self):
        """
        Negative case. Dict
        :return:
        """
        result_to_compare = [
            {"name": "abcd", "status": True, "disabled": False},
            {"name": "mno", "status": True, "disabled": False}
        ]
        args = {
            "type": "list",
            "match": [
                {"name": "abcd", "status": True, "disabled": False},
                {"name": "mnop", "status": True, "disabled": False}
            ]
        }
        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (True, "Pass")
            status, result = list_comparator.match("test-1", result_to_compare, args)
            self.assertFalse(status)

    def test_match6(self):
        """
        Negative case. String
        :return:
        """
        result_to_compare = [
            "test-str1",
            "test-str2"
        ]
        args = {
            "type": "list",
            "match": [
                "test-str",
                "test-str2"
            ]
        }
        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (True, "Pass")
            status, result = list_comparator.match("test-1", result_to_compare, args)
            self.assertFalse(status)


class TestListMatchAny(TestCase):
    """
    Unit tests for list::match_any comparator
    """

    def test_match_any1(self):
        """
        Positive test
        """
        result_to_compare = [
            {"name": "abcd", "status": True, "disabled": False},
            {"name": "mno", "status": True, "disabled": False}
        ]
        args = {
            "type": "list",
            "match_any": [
                {"name": "abc", "status": True},
                {"name": "xyz", "status": True}
            ]
        }
        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (True, "Pass")
            status, result = list_comparator.match_any("test-1", result_to_compare, args)
            self.assertTrue(status)

    def test_match_any4(self):
        """
        entry did not match
        """
        result_to_compare = [
            "rsh", "splunk"
        ]
        args = {
            "type": "list",
            "match_any": [
                "abc", "cde", "def"
            ]
        }

        status, result = list_comparator.match_any("test-1", result_to_compare, args)
        self.assertFalse(status)

    def test_match_any5(self):
        """
        Found entry from list of string
        """
        result_to_compare = [
            "rsh", "splunk"
        ]
        args = {
            "type": "list",
            "match_any": [
                "abc",
                {"def": {
                    "type": "string",
                    "match": "rsh"
                }}
            ]
        }

        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (True, "Pass")
            status, result = list_comparator.match_any("test-1", result_to_compare, args)
            self.assertTrue(status)

    def test_match_any6(self):
        """
        Found entry from list of string
        """
        result_to_compare = [
            "rsh", "splunk"
        ]
        args = {
            "type": "list",
            "match_any": [
                "abc",
                "rsh"
            ]
        }

        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (True, "Pass")
            status, result = list_comparator.match_any("test-1", result_to_compare, args)
            self.assertTrue(status)

    def test_match_any2(self):
        """
        Positive test
        """
        result_to_compare = [
            {"name": "abc", "status": True, "disabled": False},
            {"name": "mno", "status": True, "disabled": False}
        ]
        args = {
            "type": "list",
            "match_any": [
                {"name": "abc", "status": True},
                {"name": "xyz", "status": True}
            ]
        }
        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (False, "Fail")
            status, result = list_comparator.match_any("test-1", result_to_compare, args)
            self.assertFalse(status)


class TestListMatchAnyIfKeyMatches(TestCase):
    """
    Unit tests for list::match_any_if_keyvalue_matches comparator
    """

    def test_match1(self):
        """
        Positive test
        """
        result_to_compare = [
            {"name": "abc", "status": True, "disabled": False},
            {"name": "mno", "status": True, "disabled": False},
        ]
        args = {
            "type": "list",
            "match_any_if_keyvalue_matches": {
                "match_key": "name",
                "args": [
                    {"name": "abc", "status": True},
                    {"name": "xyz", "status": True}
                ]
            }
        }

        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (False, "Fail")
            status, result = list_comparator.match_any_if_keyvalue_matches("test-1", result_to_compare, args)
            self.assertFalse(status)

    def test_match2(self):
        """
        Key did not find. Still true
        """
        result_to_compare = [
            {"name": "abcd", "status": True, "disabled": False},
            {"name": "mno", "status": True, "disabled": False},
        ]
        args = {
            "type": "list",
            "match_any_if_keyvalue_matches": {
                "match_key": "name",
                "args": [
                    {"name": "abc", "status": True},
                    {"name": "xyz", "status": True}
                ]
            }
        }

        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (True, "pass_as_key_not_found")
            status, result = list_comparator.match_any_if_keyvalue_matches("test-1", result_to_compare, args)
            self.assertTrue(status)

    def test_match3(self):
        """
        Key matches. Still true
        """
        result_to_compare = [
            {"name": "abc", "status": True, "disabled": False},
            {"name": "mno", "status": True, "disabled": False},
        ]
        args = {
            "type": "list",
            "match_any_if_keyvalue_matches": {
                "match_key": "name",
                "args": [
                    {"name": "abc", "status": True},
                    {"name": "xyz", "status": True}
                ]
            }
        }

        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (True, "Pass")
            status, result = list_comparator.match_any_if_keyvalue_matches("test-1", result_to_compare, args)
            self.assertTrue(status)


class TestListMatchAll(TestCase):
    """
    Unit tests for list::match_all comparator
    """

    def test_match_all1(self):
        """
        Positive test
        """
        result_to_compare = [
            {"name": "abc", "status": True, "disabled": False},
            {"name": "mno", "status": True, "disabled": False}
        ]
        args = {
            "type": "list",
            "match_all": [
                {"name": "abc", "status": True},
                {"name": "mno", "status": True}
            ]
        }
        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (True, "Pass")
            status, result = list_comparator.match_all("test-1", result_to_compare, args)
            self.assertTrue(status)

    def test_match_all2(self):
        """
        custom comparator used
        """
        result_to_compare = [
            "abc", "xyz"
        ]
        args = {
            "type": "list",
            "match_all": [
                "abc",
                {
                    "xyz": {
                        "type": "string",
                        "match": "mno"
                    }
                }
            ]
        }
        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (True, "Pass")
            status, result = list_comparator.match_all("test-1", result_to_compare, args)
            self.assertTrue(status)

    def test_match_all3(self):
        """
        Did not match
        """
        result_to_compare = [
            "abc", "xyz"
        ]
        args = {
            "type": "list",
            "match_all": [
                "abc", "abcd"
            ]
        }
        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (True, "Pass")
            status, result = list_comparator.match_all("test-1", result_to_compare, args)
            self.assertFalse(status)


class TestListFilterCompare(TestCase):
    """
    Unit tests for list::filter_compare comparator
    """

    def test_filter_compare1(self):
        """
        Positive test
        """
        result_to_compare = [
            {"name": "abc", "status": True, "offset": 0.02},
            {"name": "abc", "status": True, "offset": 2},
            {"name": "abc", "status": True, "offset": 0.5},
        ]
        args = {
            "type": "list",
            "filter_compare": {
                "filter": {
                    "status": True,
                    "offset": {
                        "type": "number",
                        "match": "<= 5"
                    }
                },
                "compare": {
                    "size": ">= 2"
                }
            }
        }
        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (True, "Pass")
            status, result = list_comparator.filter_compare("test-1", result_to_compare, args)
            self.assertTrue(status)

    def test_filter_compare2(self):
        """
        A negative test
        Result set filered having size=1. Expected >= 2
        """
        result_to_compare = [
            {"name": "abc", "status": True, "offset": 0.02},
            {"name": "abc", "status": False, "offset": 2},
            {"name": "abc", "status": False, "offset": 0.5},
        ]
        args = {
            "type": "list",
            "filter_compare": {
                "filter": {
                    "status": True,
                    "offset": {
                        "type": "number",
                        "match": "<= 5"
                    }
                },
                "compare": {
                    "size": ">= 2"
                }
            }
        }
        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (False, "Pass")
            status, result = list_comparator.filter_compare("test-1", result_to_compare, args)
            self.assertFalse(status)
