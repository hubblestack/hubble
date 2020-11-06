from unittest import TestCase

from hubblestack.extmods.comparators import version as version_comparator


class TestVersionMatch(TestCase):
    """
    Unit tests for version::match comparator
    """
    def test_match1(self):
        """
        Match simple version. Positive test
        """
        result_to_compare = '3.28.0-1.el7'
        args = {
            "type": "version",
            "match": '3.28.0-1.el7'
        }
        status, result = version_comparator.match("test-1", result_to_compare, args)
        self.assertTrue(status)

    def test_match3(self):
        """
        Match simple version. Negative test
        """
        result_to_compare = '3.28.0-1.el7'
        args = {
            "type": "version",
            "match": '3.28.0-1.el4'
        }
        status, result = version_comparator.match("test-1", result_to_compare, args)
        self.assertFalse(status)

    def test_match2(self):
        """
        Match simple version with operator
        """
        result_to_compare = '3.28.0-1.el7'
        
        args = {"match": '==3.28.0-1.el7'}
        status, result = version_comparator.match("test-1", result_to_compare, args)
        self.assertTrue(status)

        args = {"match": '<=3.28.0-1.el7'}
        status, result = version_comparator.match("test-1", result_to_compare, args)
        self.assertTrue(status)

        args = {"match": '>=3.28.0-1.el7'}
        status, result = version_comparator.match("test-1", result_to_compare, args)
        self.assertTrue(status)

        args = {"match": '!=3.18.0-1.el7'}
        status, result = version_comparator.match("test-1", result_to_compare, args)
        self.assertTrue(status)

        args = {"match": '>3.18.0-1.el7'}
        status, result = version_comparator.match("test-1", result_to_compare, args)
        self.assertTrue(status)

        args = {"match": '<3.38.0-1.el7'}
        status, result = version_comparator.match("test-1", result_to_compare, args)
        self.assertTrue(status)

    def test_match3(self):
        """
        Match simple version with operator
        """
        args = {"match": '== 8.0.3-a6754d8441bf'}
        status, result = version_comparator.match('id', '8.0.3-a6754d8441bf', args)
        self.assertTrue(status)

        args = {"match": '<= 8.0.3-a6754d8441bg'}
        status, result = version_comparator.match('id', '8.0.3-a6754d8441bf', args)
        self.assertTrue(status)

        args = {"match": '<= 8.0.3-a6754d8441cf'}
        status, result = version_comparator.match('id', '8.0.3-a6754d8441bf', args)
        self.assertTrue(status)

        args = {"match": '> 8.0.3'}
        status, result = version_comparator.match('id', '8.0.3-a6754d8441bf', args)
        self.assertTrue(status)

        args = {"match": '> 8.0.3'}
        status, result = version_comparator.match('id', '8.0.3-a', args)
        self.assertTrue(status)

        args = {"match": '> 8.0.1'}
        status, result = version_comparator.match('id', '8.0.3-a', args)
        self.assertTrue(status)

        args = {"match": '< 8.0.3'}
        status, result = version_comparator.match('id', '8.0', args)
        self.assertTrue(status)

        args = {"match": '> 7.0'}
        status, result = version_comparator.match('id', '8.0', args)
        self.assertTrue(status)

class TestVersionMatchAny(TestCase):
    """
    Unit tests for version::match_any comparator
    """
    def test_match1(self):
        """
        should pass
        """
        result_to_compare = '3.28.0-1.el7'
        args = {"match_any": [
            '== 3.28.0-1.el6', 
            '!= 2.28.0-1.el7', 
            '< 4.28.0-1.el7'
        ]}
        status, result = version_comparator.match_any("test-1", result_to_compare, args)
        self.assertTrue(status)

    def test_match2(self):
        """
        Should fail. No match
        """
        result_to_compare = '3.28.0-1.el7'
        args = {"match_any": [
            '== 3.28.0-1.el6', 
            '<= 2.28.0-1.el7', 
            '4.28.0-1.el7'
        ]}
        status, result = version_comparator.match_any("test-1", result_to_compare, args)
        self.assertFalse(status)