
import datetime

from unittest import TestCase

from hubblestack.comparators import certificate as certificate_comparator

def datestring(days=0, fmt='%Y-%m-%d %H:%M:%S'):
    ret = datetime.datetime.now() + datetime.timedelta(days=days)
    return ret.strftime(fmt)

class TestCertificate(TestCase):
    """
    Unit tests for certificate::match
    """

    def test_match_1(self):
        """
        Match not_before and not_after. Positive test
        """
        audit_id = 'test-1'
        result_to_match = {
            'ssl_start_time': datestring(-300),
            'ssl_end_time': datestring(300)
        }
        args = {
            'match': {
                'not_before': 30,
                'not_after': 15
            }
        }
        status, result = certificate_comparator.match(audit_id, result_to_match, args)
        self.assertTrue(status)

    def test_match_2(self):
        """
        Negative test for not_before
        """
        audit_id = 'test-2'
        result_to_match = {
            'ssl_start_time': datestring(300),
            'ssl_end_time': datestring(300),
        }
        args = {
            'match': {
                'not_before': 30,
                'not_after': 15
            }
        }
        status, result = certificate_comparator.match(audit_id, result_to_match, args)
        self.assertFalse(status)
        self.assertTrue('The certificate will be valid in more than' in result)

    def test_match_3(self):
        """
        Negative test for not_after
        """
        audit_id = 'test-3'
        result_to_match = {
            'ssl_start_time': datestring(-300),
            'ssl_end_time': datestring(-15),
        }
        args = {
            'match': {
                'not_before': 30,
                'not_after': 15
            }
        }
        status, result = certificate_comparator.match(audit_id, result_to_match, args)
        self.assertFalse(status)
        self.assertTrue('The certificate will expire in less than' in result)

    def test_match_4(self):
        """
        Negative test for fail_if_not_before
        """
        audit_id = 'test-4'
        result_to_match = {
            'ssl_start_time': datestring(300),
            'ssl_end_time': datestring(600)
        }
        args = {
            'match': {
                'fail_if_not_before': True,
                'not_after': 15,
                'not_before': 0
            }
        }
        status, result = certificate_comparator.match(audit_id, result_to_match, args)
        self.assertFalse(status)
        self.assertTrue('The certificate is not yet valid' in result)

    def test_match_5(self):
        """
        Positive test for extra param 'ssl_issuer_common_name'
        """
        audit_id = 'test-5'
        result_to_match = {
            'ssl_start_time': datestring(-300),
            'ssl_end_time': datestring(300),
            'ssl_issuer_common_name' : 'DigiCert SHA2 Secure Server CA'
        }
        args = {
            'match': {
                'not_before': 30,
                'not_after': 15,
                'ssl_issuer_common_name': 'DigiCert SHA2 Secure Server CA'
            }
        }
        status, result = certificate_comparator.match(audit_id, result_to_match, args)
        self.assertTrue(status)

    def test_match_6(self):
        """
        Negative test for extra param 'ssl_issuer_common_name'
        """
        audit_id = 'test-5'
        result_to_match = {
            'ssl_start_time': datestring(-300),
            'ssl_end_time': datestring(300),
            'ssl_issuer_common_name' : 'DigiCert SHA2 Secure Server CA'
        }
        args = {
            'match': {
                'not_before': 30,
                'not_after': 15,
                'ssl_issuer_common_name': 'DigiCert'
            }
        }
        status, result = certificate_comparator.match(audit_id, result_to_match, args)
        self.assertFalse(status)
        self.assertTrue('Value of input field: ssl_issuer_common_name does not match' in result.get('ssl_issuer_common_name'))
