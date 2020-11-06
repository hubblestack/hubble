from unittest import TestCase
import pytest

from hubblestack.extmods.hubble_mods import pkg
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestPkg(TestCase):
    """
    Unit tests for pkg module
    """

    def testValidateParams1(self):
        """
        Mandatory param passed. Test should pass
        """
        block_id = "test-1"
        block_dict = {'args':
            {
                'name': 'perl'
            }
        }
        pkg.validate_params(block_id, block_dict, {})

    def testValidateParams2(self):
        """
        Mandatory param name not passed. Test should raise HubbleCheckValidationError
        """
        block_id = "test-2"
        block_dict = {'args':
            {
            }
        }

        with pytest.raises(HubbleCheckValidationError) as exception:
            pkg.validate_params(block_id, block_dict, {})
            pytest.fail('Should not have passed')
        self.assertTrue('Mandatory parameter: name not found' in str(exception.value))

    def testFilteredLogs1(self):
        """
        Check filtered logs output
        """
        block_id = "test-3"
        block_dict = {'args':
            {
                'name': 'perl',
            }
        }
        expected_dict = {'name': 'perl'}
        result = pkg.get_filtered_params_to_log(block_id, block_dict, {})
        self.assertDictEqual(expected_dict, result)

    def testExecute1(self):
        """
        Query for a package. It should return a single result
        """
        test_dict = {"test-package": "1.0.4",
                     "package" : "2.1.2"}

        def _list_pkgs():
            return test_dict

        pkg.__salt__ = {
            'pkg.list_pkgs': _list_pkgs
        }

        block_id = "test-4"
        block_dict = {'args':
            {
                'name': 'test-package',
            }
        }
        expected_dict = {"result": {
            "test-package": "1.0.4"
        }
        }
        status, result_dict = pkg.execute(block_id, block_dict, {})
        self.assertTrue(status)
        self.assertDictEqual(expected_dict, result_dict)

    def testExecute2(self):
        """
        Query for a package. It is not installed. Empty dict should be returned
        """
        test_dict = {"package" : "2.1.2"}

        def _list_pkgs():
            return test_dict

        pkg.__salt__ = {
            'pkg.list_pkgs': _list_pkgs
        }

        block_id = "test-5"
        block_dict = {'args':
            {
                'name': 'test-package',
            }
        }
        expected_dict = {"result": {}}
        status, result_dict = pkg.execute(block_id, block_dict, {})
        self.assertTrue(status)
        self.assertDictEqual(expected_dict, result_dict)

    def testExecute3(self):
        """
        Query for a package. Check for regex in name
        """
        test_dict = {"perl" : "2.1.2",
                     "perl-libs": "1.2.3",
                     "test-package": "4.5.6"}

        def _list_pkgs():
            return test_dict

        pkg.__salt__ = {
            'pkg.list_pkgs': _list_pkgs
        }

        block_id = "test-6"
        block_dict = {'args':
            {
                'name': 'perl*',
            }
        }
        expected_dict = {"result": {
            "perl": "2.1.2",
            "perl-libs": "1.2.3"
        }}
        status, result_dict = pkg.execute(block_id, block_dict, {})
        self.assertTrue(status)
        self.assertDictEqual(expected_dict, result_dict)

    def testExecute4(self):
        """
        Query for a package. Check for regex * in name.
        """
        test_dict = {"perl" : "2.1.2",
                     "perl-libs": "1.2.3",
                     "test-package": "4.5.6"}

        def _list_pkgs():
            return test_dict

        pkg.__salt__ = {
            'pkg.list_pkgs': _list_pkgs
        }

        block_id = "test-7"
        block_dict = {'args':
            {
                'name': '*',
            }
        }
        expected_dict = {"result": test_dict}
        status, result_dict = pkg.execute(block_id, block_dict, {})
        self.assertTrue(status)
        self.assertDictEqual(expected_dict, result_dict)