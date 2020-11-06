from unittest import TestCase

import hubblestack.extmods.comparators.file_permission as fp_comparator


class TestFilePermissionMatch(TestCase):
    """
    Unit tests for file_permission::match comparator
    """

    def test_match1(self):
        """
        Positive test
        """
        args = {
            "type": "file_permission",
            "match": {
                "required_value": "644",
                "allow_more_strict": "true"
            }
        }
        status, result = fp_comparator.match("test-1", "0644", args)
        self.assertTrue(status)

    def test_match2(self):
        """
        Must fail, allow_more_strict=true
        """
        args = {
            "type": "file_permission",
            "match": {
                "required_value": "644",
                "allow_more_strict": "true"
            }
        }
        status, result = fp_comparator.match("test-1", "0645", args)
        self.assertFalse(status)

    def test_match3(self):
        """
        Must fail, allow_more_strict=true
        """
        args = {
            "type": "file_permission",
            "match": {
                "required_value": "644",
                "allow_more_strict": "true"
            }
        }
        status, result = fp_comparator.match("test-1", "0643", args)
        self.assertFalse(status)

    def test_match4(self):
        """
        Must fail, allow_more_strict=false
        """
        args = {
            "type": "file_permission",
            "match": {
                "required_value": "644",
                "allow_more_strict": "false"
            }
        }
        status, result = fp_comparator.match("test-1", "0643", args)
        self.assertFalse(status)

    def test_match5(self):
        """
        Must pass, allow_more_strict=false
        """
        args = {
            "type": "file_permission",
            "match": {
                "required_value": "644",
                "allow_more_strict": "false"
            }
        }
        status, result = fp_comparator.match("test-1", "0644", args)
        self.assertTrue(status)
