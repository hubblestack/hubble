from unittest import TestCase
from unittest.mock import patch

import hubblestack.comparators.dict as dict_comparator


class TestDictMatch(TestCase):
    """
    Unit tests for dict::match comparator
    """

    def test_match1(self):
        """
        Positive test
        """
        result_to_compare = {
            "uid": 0,
            "gid": 0,
            "group": "root",
            "misc": "xyz"
        }
        args = {
            "type": "dict",
            "match": {
                "uid": 0,
                "gid": 0
            }
        }
        status, result = dict_comparator.match("test-1", result_to_compare, args)
        self.assertTrue(status)

    def test_match2(self):
        """
        Must fail
        """
        result_to_compare = {
            "uid": 0,
            "gid": 0,
            "group": "root",
            "misc": "xyz"
        }
        args = {
            "type": "dict",
            "match": {
                "uid": 1,
                "gid": 0
            }
        }
        status, result = dict_comparator.match("test-1", result_to_compare, args)
        self.assertFalse(status)

    def test_match3(self):
        """
        Nested dictionary. Must pass
        """
        result_to_compare = {
            '/abc': {
                'device': '/dev/sda3',
                'test': {
                    "k1": "v1",
                    "k2": "v2",
                    "k3": {
                        "k1": "v1",
                        "k2": "v2"
                    }
                },
                'fstype': 'xfs',
                'opts': ['rw', 'seclabel', 'relatime', 'attr2', 'inode64', 'noquota']
            },
            '/sys': {
                'device': '/dev/sda1',
                'fstype': 'xfs3',
                'opts': ['rw', 'seclabel', 'relatime', 'attr2', 'inode64', 'noquota']
            },
        }
        args = {
            "type": "dict",
            "match": {
                "/abc": {
                    'device': '/dev/sda3',
                    'test': {
                        "k1": "v1",
                        "k3": {
                            "k2": "v2"
                        }
                    },
                }
            }
        }
        status, result = dict_comparator.match("test-1", result_to_compare, args)
        self.assertTrue(status)

    def test_match4(self):
        """
        Nested dictionary, with extra comparator
        """
        result_to_compare = {
            '/abc': {
                'device': '/dev/sda3',
                'test': {
                    "k1": "v1",
                    "k2": "v2",
                    "k3": {
                        "k1": "v1",
                        "k2": "v2"
                    }
                },
                'fstype': 'xfs',
                'opts': ['rw', 'seclabel', 'relatime', 'attr2', 'inode64', 'noquota']
            },
            '/sys': {
                'device': '/dev/sda1',
                'fstype': 'xfs3',
                'opts': ['rw', 'seclabel', 'relatime', 'attr2', 'inode64', 'noquota']
            },
        }
        args = {
            "type": "dict",
            "match": {
                "/abc": {
                    'device': '/dev/sda3',
                    'test': {
                        "k1": "v1",
                        "k3": {
                            "k2": "v2"
                        }
                    },
                    'fstype': {
                        'type': 'string',
                        'match_any': [
                            'xfs',
                            'xfs2'
                        ]
                    }
                }
            }
        }

        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (True, "Pass")
            status, result = dict_comparator.match("test-1", result_to_compare, args)
            self.assertTrue(status)

    def test_match5(self):
        """
        Key not found
        """
        result_to_compare = {
            "uid": 0,
            "gid": 0,
            "group": "root",
            "misc": "xyz"
        }
        args = {
            "type": "dict",
            "match": {
                "user": 0,
                "gid": 0
            }
        }
        status, result = dict_comparator.match("test-1", result_to_compare, args)
        self.assertFalse(status)

    def test_match6(self):
        """
        Nested dictionary, with extra comparator
        """
        result_to_compare = {
            '/abc': {
                'device': '/dev/sda3',
                'test': {
                    "k1": "v1",
                    "k2": "v2",
                    "k3": {
                        "k1": "v1",
                        "k2": "v2"
                    }
                },
                'fstype': 'xfs',
                'opts': ['rw', 'seclabel', 'relatime', 'attr2', 'inode64', 'noquota']
            },
            '/sys': {
                'device': '/dev/sda1',
                'fstype': 'xfs3',
                'opts': ['rw', 'seclabel', 'relatime', 'attr2', 'inode64', 'noquota']
            },
        }
        args = {
            "type": "dict",
            "match": {
                "/abc": {
                    'device': '/dev/sda3',
                    'test': {
                        "k1": "v1",
                        "k3": {
                            "k2": "v2"
                        }
                    },
                    'fstype': {
                        'type': 'string',
                        'match_any': [
                            'xfs',
                            'xfs2'
                        ]
                    }
                }
            }
        }

        with patch('hubblestack.module_runner.comparator') as comparator_mock:
            comparator_mock.run.return_value = (False, "Failed")
            status, result = dict_comparator.match("test-1", result_to_compare, args)
            self.assertFalse(status)


class TestDictMatchKeyAny(TestCase):
    """
    Unit tests for dict::match_key_any comparator
    """

    def test_match1(self):
        """
        Positive test
        """
        result_to_compare = {
            "/abc": {"k1": "v1"},
            "/xyz": {"k2": "v2"},
            "/mno": {"k3": "v3"}
        }
        args = {
            "type": "dict",
            "match_key_any": [
                "/", "/xyz"
            ]
        }
        status, result = dict_comparator.match_key_any("test-1", result_to_compare, args)
        self.assertTrue(status)

    def test_match2(self):
        """
        Negative test
        """
        result_to_compare = {
            "/abc": {"k1": "v1"},
            "/xyz": {"k2": "v2"},
            "/mno": {"k3": "v3"}
        }
        args = {
            "type": "dict",
            "match_key_any": [
                "/", "/sys"
            ]
        }
        status, result = dict_comparator.match_key_any("test-1", result_to_compare, args)
        self.assertFalse(status)


class TestDictMatchKeyAll(TestCase):
    """
    Unit tests for dict::match_key_all comparator
    """

    def test_match1(self):
        """
        Positive test
        """
        result_to_compare = {
            "/abc": {"k1": "v1"},
            "/xyz": {"k2": "v2"},
            "/mno": {"k3": "v3"}
        }
        args = {
            "type": "dict",
            "match_key_all": [
                "/abc", "/xyz"
            ]
        }
        status, result = dict_comparator.match_key_all("test-1", result_to_compare, args)
        self.assertTrue(status)

    def test_match2(self):
        """
        Negative test
        """
        result_to_compare = {
            "/abc": {"k1": "v1"},
            "/xyz": {"k2": "v2"},
            "/mno": {"k3": "v3"}
        }
        args = {
            "type": "dict",
            "match_key_all": [
                "/abc", "/sys"
            ]
        }
        status, result = dict_comparator.match_key_all("test-1", result_to_compare, args)
        self.assertFalse(status)


class TestDictMatchAny(TestCase):
    """
    Unit tests for dict::match_any comparator
    """

    def test_match_any1(self):
        """
        Positive test
        """
        result_to_compare = {"name": "abc", "status": True, "disabled": False}
        args = {
            "type": "dict",
            "match_any": [
                {"name": "abc", "status": True},
                {"name": "xyz", "status": True}
            ]
        }
        status, result = dict_comparator.match_any("test-1", result_to_compare, args)
        self.assertTrue(status)

    def test_match_any2(self):
        """
        Negative test
        """
        result_to_compare = {"name": "abc", "status": True, "disabled": False}
        args = {
            "type": "dict",
            "match_any": [
                {"name": "abcd", "status": True},
                {"name": "xyz", "status": True}
            ]
        }
        status, result = dict_comparator.match_any("test-1", result_to_compare, args)
        self.assertFalse(status)


class TestDictMatchAnyIfKeyMatches(TestCase):
    """
    Unit tests for dict::match_any_if_keyvalue_matches comparator
    """

    def test_match1(self):
        """
        Positive test
        """
        result_to_compare = {"name": "abc", "status": True, "disabled": False}
        args = {
            "type": "dict",
            "match_any_if_keyvalue_matches": {
                "match_key": "name",
                "args": [
                    {"name": "abc", "status": True},
                    {"name": "xyz", "status": True}
                ]
            }
        }
        status, result = dict_comparator.match_any_if_keyvalue_matches("test-1", result_to_compare, args)
        self.assertTrue(status)

    def test_match2(self):
        """
        Should pass. match_key doesnt exist
        """
        result_to_compare = {"name": "abc", "status": True, "disabled": False}
        args = {
            "type": "dict",
            "match_any_if_keyvalue_matches": {
                "match_key": "name",
                "args": [
                    {"name": "abcd", "status": True},
                    {"name": "xyz", "status": True}
                ]
            }
        }
        status, result = dict_comparator.match_any_if_keyvalue_matches("test-1", result_to_compare, args)
        self.assertTrue(status)
        self.assertEqual(result, 'pass_as_keyvalue_not_found')

    def test_match3(self):
        """
        Should fail. Key found but didnt match
        """
        result_to_compare = {"name": "abc", "status": True, "disabled": False}
        args = {
            "type": "dict",
            "match_any_if_keyvalue_matches": {
                "match_key": "name",
                "args": [
                    {"name": "abc", "status": False},
                    {"name": "xyz", "status": True}
                ]
            }
        }
        status, result = dict_comparator.match_any_if_keyvalue_matches("test-1", result_to_compare, args)
        self.assertFalse(status)
