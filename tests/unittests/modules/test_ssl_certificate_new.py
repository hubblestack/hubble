from unittest import TestCase
from unittest.mock import patch
import pytest

from hubblestack.extmods.hubble_mods import ssl_certificate
from hubblestack.utils.hubble_error import HubbleCheckValidationError


class TestSSL(TestCase):
    """
    Unit tests for ssl_certificate module
    """

    def testValidateParams1(self):
        """
        Mandatory param host and port passed. Test should pass
        """
        block_id = "test-1"
        block_dict = {'args':
            {
                'host_ip': '1.2.3.4',
                'host_port': 1234
            }
        }
        extra_args = {
            'caller': 'Audit'
        }
        ssl_certificate.validate_params(block_id, block_dict, extra_args)

    def testValidateParams2(self):
        """
        Mandatory param path passed. Test should pass
        """
        block_id = "test-2"
        block_dict = {'args':
            {
                'path': 'dummy path'
            }
        }
        extra_args = {
            'caller': 'Audit'
        }
        ssl_certificate.validate_params(block_id, block_dict, extra_args)

    def testValidateParams3(self):
        """
        Mandatory param path and host, port passed. Test should raise HubbleCheckValidationError
        """
        block_id = "test-3"
        block_dict = {'args':
            {
                'host_ip': '1.2.3.4',
                'host_port': 1234,
                'path': 'dummy path'
            }
        }
        extra_args = {
            'caller': 'Audit'
        }
        with pytest.raises(HubbleCheckValidationError) as exception:
            ssl_certificate.validate_params(block_id, block_dict, extra_args)
            pytest.fail('Should not have passed')
        self.assertTrue('Only one of either endpoint data or path is required not both' in str(exception.value))

    def testValidateParams4(self):
        """
        Mandatory param path and host, port not passed. Test should raise HubbleCheckValidationError
        """
        block_id = "test-4"
        block_dict = {'args':
            {
                'name': 'dummy value'
            }
        }
        extra_args = {
            'caller': 'Audit'
        }
        with pytest.raises(HubbleCheckValidationError) as exception:
            ssl_certificate.validate_params(block_id, block_dict, extra_args)
            pytest.fail('Should not have passed')
        self.assertTrue('Mandatory parameter: host_ip, host_port or path not found' in str(exception.value))

    def testValidateParams5(self):
        """
        Incorrect value of param ssl_timeout passed. Test should raise HubbleCheckValidationError
        """
        block_id = "test-5"
        block_dict = {'args':
            {
                'host_ip': '1.2.3.4',
                'host_port': 1234,
                'ssl_timeout': -3
            }
        }
        extra_args = {
            'caller': 'Audit'
        }
        with pytest.raises(HubbleCheckValidationError) as exception:
            ssl_certificate.validate_params(block_id, block_dict, extra_args)
            pytest.fail('Should not have passed')
        self.assertTrue('Incorrect value provided for ssl_timeout' in str(exception.value))

    def testFilteredLogs1(self):
        """
        Check filtered logs output for host, port
        """
        block_id = "test-6"
        block_dict = {'args':
            {
                'host_ip': '1.2.3.4',
                'host_port': 1234,
            }
        }
        expected_dict = {'host_ip': '1.2.3.4',
                         'host_port': 1234}
        result = ssl_certificate.get_filtered_params_to_log(block_id, block_dict)
        self.assertDictEqual(expected_dict, result)

    def testFilteredLogs2(self):
        """
        Check filtered logs output for path
        """
        block_id = "test-7"
        block_dict = {'args':
            {
                'path': 'dummy path'
            }
        }
        expected_dict = {'path': 'dummy path'}
        result = ssl_certificate.get_filtered_params_to_log(block_id, block_dict)
        self.assertDictEqual(expected_dict, result)

    @patch('hubblestack.extmods.hubble_mods.ssl_certificate._get_cert')
    def testExecute1(self, get_cert_mock):
        """
        Run execute for a common test case - google
        Match the expected output
        """
        block_id = "test-8"
        block_dict = {'args':
            {
                'host_ip': 'www.google.com',
                'host_port': 443
            }
        }
        get_cert_mock.return_value = "-----BEGIN CERTIFICATE-----\n" \
                                     "MIIDfDCCAmSgAwIBAgIJAJB2iRjpM5OgMA0GCSqGSIb3DQEBCwUAME4xMTAvBgNV\n" \
                                     "BAsMKE5vIFNOSSBwcm92aWRlZDsgcGxlYXNlIGZpeCB5b3VyIGNsaWVudC4xGTAX\n" \
                                     "BgNVBAMTEGludmFsaWQyLmludmFsaWQwHhcNMTUwMTAxMDAwMDAwWhcNMzAwMTAx\n" \
                                     "MDAwMDAwWjBOMTEwLwYDVQQLDChObyBTTkkgcHJvdmlkZWQ7IHBsZWFzZSBmaXgg\n" \
                                     "eW91ciBjbGllbnQuMRkwFwYDVQQDExBpbnZhbGlkMi5pbnZhbGlkMIIBIjANBgkq\n" \
                                     "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzWJP5cMThJgMBeTvRKKl7N6ZcZAbKDVA\n" \
                                     "tNBNnRhIgSitXxCzKtt9rp2RHkLn76oZjdNO25EPp+QgMiWU/rkkB00Y18Oahw5f\n" \
                                     "i8s+K9dRv6i+gSOiv2jlIeW/S0hOswUUDH0JXFkEPKILzpl5ML7wdp5kt93vHxa7\n" \
                                     "HswOtAxEz2WtxMdezm/3CgO3sls20wl3W03iI+kCt7HyvhGy2aRPLhJfeABpQr0U\n" \
                                     "ku3q6mtomy2cgFawekN/X/aH8KknX799MPcuWutM2q88mtUEBsuZmy2nsjK9J7/y\n" \
                                     "hhCRDzOV/yY8c5+l/u/rWuwwkZ2lgzGp4xBBfhXdr6+m9kmwWCUm9QIDAQABo10w\n" \
                                     "WzAOBgNVHQ8BAf8EBAMCAqQwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC\n" \
                                     "MA8GA1UdEwEB/wQFMAMBAf8wGQYDVR0OBBIEELsPOJZvPr5PK0bQQWrUrLUwDQYJ\n" \
                                     "KoZIhvcNAQELBQADggEBALnZ4lRc9WHtafO4Y+0DWp4qgSdaGygzS/wtcRP+S2V+\n" \
                                     "HFOCeYDmeZ9qs0WpNlrtyeBKzBH8hOt9y8aUbZBw2M1F2Mi23Q+dhAEUfQCOKbIT\n" \
                                     "tunBuVfDTTbAHUuNl/eyr78v8Egi133z7zVgydVG1KA0AOSCB+B65glbpx+xMCpg\n" \
                                     "ZLux9THydwg3tPo/LfYbRCof+Mb8I3ZCY9O6FfZGjuxJn+0ux3SDora3NX/FmJ+i\n" \
                                     "kTCTsMtIFWhH3hoyYAamOOuITpPZHD7yP0lfbuncGDEqAQu2YWbYxRixfq2VSxgv\n" \
                                     "gWbFcmkgBLYpE8iDWT3Kdluo1+6PHaDaLg2SacOY6Go=\n" \
                                     "-----END CERTIFICATE-----"
        result_list = []
        extra_args = {
            'extra_args': result_list
        }
        expected_dict = {
            "result": {
                'ssl_src_port': '443',
                'ssl_src_host': 'www.google.com',
                'ssl_src_path': 'None',
                'ssl_issuer_common_name': 'None',
                'ssl_subject_country': 'None',
                'ssl_subject_organisation': 'None',
                'ssl_subject_organisation_unit': 'None',
                'ssl_subject_common_name': 'None',
                'ssl_cert_version': '2',
                'ssl_has_expired': False,
                'ssl_serial_number': '10409658328798172064',
                'ssl_end_time': '2030-01-01 00:00:00',
                'ssl_start_time': '2015-01-01 00:00:00',
                'ssl_signature_algorithm': "b'sha256WithRSAEncryption'"}
        }
        status, res = ssl_certificate.execute(block_id,block_dict, extra_args)
        self.assertTrue(status)
        self.assertTrue(expected_dict.get('result').items() <= res.get('result').items())

    @patch('hubblestack.extmods.hubble_mods.ssl_certificate._get_cert')
    def testExecute2(self, get_cert_mock):
        """
        Run execute for a negative case
        Match the expected output
        """
        block_id = "test-9"
        block_dict = {'args':
            {
                'host_ip': 'www.google.com',
                'host_port': 443
            }
        }
        get_cert_mock.return_value = None
        result_list = []
        extra_args = {
            'extra_args': result_list
        }
        status, res = ssl_certificate.execute(block_id,block_dict, extra_args)
        self.assertFalse(status)
        self.assertEqual(res, {'error': 'unable_to_load_certificate'})