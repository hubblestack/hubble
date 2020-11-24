# coding: utf-8
import os
import ssl
import mock
import hubblestack.extmods.fdg.ssl_certificate


def test_load_certificate_exception():
    host = 'google.com'
    port = 443
    ssl.get_server_certificate = mock.Mock(side_effect=Exception('Test Exception'))
    val = hubblestack.extmods.fdg.ssl_certificate._load_certificate(host, port, 3)
    assert val.get('result') == False

def test_load_certificate():
    host = 'google.com'
    port = 443
    cert_details = {'pem_cert': '---BEGIN CERTIFICATE---- ---END CERTIFICATE----'}
    ssl.get_server_certificate = mock.Mock(return_value=cert_details)
    val = hubblestack.extmods.fdg.ssl_certificate._load_certificate(host, port, 3)
    assert val.get('result') == True

def test_parse_cert_positive():
    pem_file = get_pem_file()
    cert = {'data':pem_file}
    host = 'google.com'
    port = 443
    val = hubblestack.extmods.fdg.ssl_certificate._parse_cert(cert, host, port)
    assert ('error' not in val.keys())

def test_parse_cert_negative():
    cert = {'data':''}
    host = 'google.com'
    port = 443
    val = hubblestack.extmods.fdg.ssl_certificate._parse_cert(cert, host, port)
    assert ('error' in val.keys())

def test_ssl_certificate_positive():
    params = {'params': {'host_ip':'google.com', 'host_port':443}}
    cert_details = {'pem_cert':'---BEGIN CERTIFICATE---- ---END CERTIFICATE----'}
    cert = {'result':True,'data':cert_details}
    hubblestack.extmods.fdg.ssl_certificate._load_certificate = mock.Mock(return_value=cert)
    hubblestack.extmods.fdg.ssl_certificate._parse_cert = mock.Mock(return_value=cert_details)
    val = hubblestack.extmods.fdg.ssl_certificate.get_cert_details(params)
    assert val[0] == True
    assert val[1].get('pem_cert') != None

def test_ssl_certificate_negative():
    params = {'params': {'host_ip': '127.0.0.1', 'host_port': 443}}
    cert = {'result':False,'data':'cert not found'}
    hubblestack.extmods.fdg.ssl_certificate._load_certificate = mock.Mock(return_value=cert)
    val = hubblestack.extmods.fdg.ssl_certificate.get_cert_details(params)
    assert val[0] == True
    assert val[1].get('pem_cert') == None

def test_null_value():
    params = {'params': {'host_ip': '', 'host_port': 443}}
    val = hubblestack.extmods.fdg.ssl_certificate.get_cert_details(params)
    assert val[0] == False
    assert val[1] == ''

def test_garbage_value():
    params = {'params': {'host_ip': 'ag#786asf kjas.{\\}', 'host_port': 443}}
    val = hubblestack.extmods.fdg.ssl_certificate.get_cert_details(params)
    assert val[0] == False
    assert val[1] == ''

def test_invalid_input():
    params = {'params': {'host_p': 'google.com', 'host_po': 443}}
    val = hubblestack.extmods.fdg.ssl_certificate.get_cert_details(params)
    assert val[0] == False
    assert val[1] == ''

def test_chained_positive():
    chained = {'host_ip': 'google.com', 'host_port': 443}
    cert_details = {'pem_cert': '---BEGIN CERTIFICATE---- ---END CERTIFICATE----'}
    cert = {'result': True, 'data': cert_details}
    hubblestack.extmods.fdg.ssl_certificate._load_certificate = mock.Mock(return_value=cert)
    hubblestack.extmods.fdg.ssl_certificate._parse_cert = mock.Mock(return_value=cert_details)
    val = hubblestack.extmods.fdg.ssl_certificate.get_cert_details(chained=chained)
    assert val[0] == True
    assert val[1].get('pem_cert') != None

def test_chained_negative():
    chained = {'host_ip': '127.0.0.1', 'host_port': 0}
    cert = {'result': False, 'data': 'cert not found'}
    hubblestack.extmods.fdg.ssl_certificate._load_certificate = mock.Mock(return_value=cert)
    val = hubblestack.extmods.fdg.ssl_certificate.get_cert_details(chained=chained)
    assert val[0] == True
    assert val[1].get('pem_cert') == None

def test_chained_null_value():
    chained = {'host_ip': '', 'host_port': 443}
    val = hubblestack.extmods.fdg.ssl_certificate.get_cert_details(chained=chained)
    assert val[0] == False
    assert val[1] == ''

def test_chained_invalid_input():
    chained = {'host_i': 'google.com', 'host_po': 443}
    val = hubblestack.extmods.fdg.ssl_certificate.get_cert_details(chained=chained)
    assert val[0] == False
    assert val[1] == ''

def test_chained_garbage_value():
    chained = {'host_ip': 'ag#786asf kjas.{\\}', 'host_port': 443}
    val = hubblestack.extmods.fdg.ssl_certificate.get_cert_details(chained=chained)
    assert val[0] == False
    assert val[1] == ''

def test_check_input_validity_positive():
    host = 'google.com'
    port = 443
    val = hubblestack.extmods.fdg.ssl_certificate._check_input_validity(host, port, 3)
    assert val == True

def test_check_input_validity_negative():
    host = ''
    port = -1
    val = hubblestack.extmods.fdg.ssl_certificate._check_input_validity(host, port, 3)
    assert val == False

def test_check_input_validity_negative_spaces():
    host = 'ag#786asf kjas.{\\}'
    port = 443
    val = hubblestack.extmods.fdg.ssl_certificate._check_input_validity(host, port, 3)
    assert val == False

def get_pem_file():
    return '-----BEGIN CERTIFICATE-----\nMIIKDzCCCPegAwIBAgIQQCqYIy3IbBMIAAAAAB2JsTANBgkqhkiG9w0BAQsFADBC\nMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMRMw\nEQYDVQQDEwpHVFMgQ0EgMU8xMB4XDTE5MTEwNTA3MzgzMloXDTIwMDEyODA3Mzgz\nMlowZjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT\nDU1vdW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBMTEMxFTATBgNVBAMMDCou\nZ29vZ2xlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALzpwqd4\njwhnMoy+qZEKCeSGOsISNramQEYoJv0O3y+DQuItbSvOHBDDc8SNkZU7rAydnxxE\nIBq06hbXUoTeUZL+zeAYvZgnq08utlPlOeMyHbOIFRt8PM14WdNzjFwFpJZDuIbW\nOBuicnaV/TVjmq6VcfQrrA5fBgn8UUTzwTyneV7utk+bHb6mhu44KejwvbqpCp0D\nypL6uCpCEN68nid8JdMxUCC0rtmoi1gzmAJmKFIlY38ImdA4rOIGvS72TP7A847W\nsRcbPchEM3Mu2k3IrPVlkpVxUZip8UFLJ30xyMQfzxEwgdwDST7AuY0r6MH1iBrt\n2dy3zu8PxUUGAZcCAwEAAaOCBtswggbXMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUE\nDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBS0dnmZ2GwZdRtj\nQjCKEpUnNHrINzAfBgNVHSMEGDAWgBSY0fhuEOvPm+xgnxiQG6DrfQn9KzBkBggr\nBgEFBQcBAQRYMFYwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnBraS5nb29nL2d0\nczFvMTArBggrBgEFBQcwAoYfaHR0cDovL3BraS5nb29nL2dzcjIvR1RTMU8xLmNy\ndDCCBJ0GA1UdEQSCBJQwggSQggwqLmdvb2dsZS5jb22CDSouYW5kcm9pZC5jb22C\nFiouYXBwZW5naW5lLmdvb2dsZS5jb22CEiouY2xvdWQuZ29vZ2xlLmNvbYIYKi5j\ncm93ZHNvdXJjZS5nb29nbGUuY29tggYqLmcuY2+CDiouZ2NwLmd2dDIuY29tghEq\nLmdjcGNkbi5ndnQxLmNvbYIKKi5nZ3BodC5jboIOKi5na2VjbmFwcHMuY26CFiou\nZ29vZ2xlLWFuYWx5dGljcy5jb22CCyouZ29vZ2xlLmNhggsqLmdvb2dsZS5jbIIO\nKi5nb29nbGUuY28uaW6CDiouZ29vZ2xlLmNvLmpwgg4qLmdvb2dsZS5jby51a4IP\nKi5nb29nbGUuY29tLmFygg8qLmdvb2dsZS5jb20uYXWCDyouZ29vZ2xlLmNvbS5i\ncoIPKi5nb29nbGUuY29tLmNvgg8qLmdvb2dsZS5jb20ubXiCDyouZ29vZ2xlLmNv\nbS50coIPKi5nb29nbGUuY29tLnZuggsqLmdvb2dsZS5kZYILKi5nb29nbGUuZXOC\nCyouZ29vZ2xlLmZyggsqLmdvb2dsZS5odYILKi5nb29nbGUuaXSCCyouZ29vZ2xl\nLm5sggsqLmdvb2dsZS5wbIILKi5nb29nbGUucHSCEiouZ29vZ2xlYWRhcGlzLmNv\nbYIPKi5nb29nbGVhcGlzLmNughEqLmdvb2dsZWNuYXBwcy5jboIUKi5nb29nbGVj\nb21tZXJjZS5jb22CESouZ29vZ2xldmlkZW8uY29tggwqLmdzdGF0aWMuY26CDSou\nZ3N0YXRpYy5jb22CEiouZ3N0YXRpY2NuYXBwcy5jboIKKi5ndnQxLmNvbYIKKi5n\ndnQyLmNvbYIUKi5tZXRyaWMuZ3N0YXRpYy5jb22CDCoudXJjaGluLmNvbYIQKi51\ncmwuZ29vZ2xlLmNvbYITKi53ZWFyLmdrZWNuYXBwcy5jboIWKi55b3V0dWJlLW5v\nY29va2llLmNvbYINKi55b3V0dWJlLmNvbYIWKi55b3V0dWJlZWR1Y2F0aW9uLmNv\nbYIRKi55b3V0dWJla2lkcy5jb22CByoueXQuYmWCCyoueXRpbWcuY29tghphbmRy\nb2lkLmNsaWVudHMuZ29vZ2xlLmNvbYILYW5kcm9pZC5jb22CG2RldmVsb3Blci5h\nbmRyb2lkLmdvb2dsZS5jboIcZGV2ZWxvcGVycy5hbmRyb2lkLmdvb2dsZS5jboIE\nZy5jb4IIZ2dwaHQuY26CDGdrZWNuYXBwcy5jboIGZ29vLmdsghRnb29nbGUtYW5h\nbHl0aWNzLmNvbYIKZ29vZ2xlLmNvbYIPZ29vZ2xlY25hcHBzLmNughJnb29nbGVj\nb21tZXJjZS5jb22CGHNvdXJjZS5hbmRyb2lkLmdvb2dsZS5jboIKdXJjaGluLmNv\nbYIKd3d3Lmdvby5nbIIIeW91dHUuYmWCC3lvdXR1YmUuY29tghR5b3V0dWJlZWR1\nY2F0aW9uLmNvbYIPeW91dHViZWtpZHMuY29tggV5dC5iZTAhBgNVHSAEGjAYMAgG\nBmeBDAECAjAMBgorBgEEAdZ5AgUDMC8GA1UdHwQoMCYwJKAioCCGHmh0dHA6Ly9j\ncmwucGtpLmdvb2cvR1RTMU8xLmNybDCCAQUGCisGAQQB1nkCBAIEgfYEgfMA8QB2\nALIeBcyLos2KIE6HZvkruYolIGdr2vpw57JJUy3vi5BeAAABbjq3OwwAAAQDAEcw\nRQIgSc9iSlOtErm1c6Qbii3f68BqGlz0Q9aHFOa/D0HVZuMCIQCt/KOKSR0hC2PK\n6I6dRrGMtHkByaNOlc1TQo94Na9WxQB3AF6nc/nfVsDntTZIfdBJ4DJ6kZoMhKES\nEoQYdZaBcUVYAAABbjq3OzYAAAQDAEgwRgIhAIf18WFuSfSrq4jVMbKSvpxgFNbS\nBpkrRjdeTK5zZBqpAiEA74KwA3lPpjhxaKRe4kyalp3Es+tPqazOAHA8p3kJNXMw\nDQYJKoZIhvcNAQELBQADggEBAHSHBklyVqqXEvcNxLLubofyewBEzfKZ7VT1ezo0\nTojAzaa27WGIadpJoxudPGS+uQ/Pcs0S3/VXjXSCvQUOuJaksqXRazFrAeFKRbrh\n2i97CE5aDxHzpcc0NNBDSgPO+Km7bJjHUGC5srku1GhW/9uod6A0+BCgNrTwnFZf\nGJhY4zBvKGJ/ztJX0POakWz+JBJXDltEccJFf7CSkTlwc+m8SNBmGMieDwJCRNg5\nODLYRVMONoXilHK1dyTfYuuXzwV8UFKmFgwJtD/fDogvVtiJZG4aoeakYt75+I+B\nhpR4lKu537vPnbsy3XtY7Ucvb5Ze1AJxh3qJ8XnxWfgLF68=\n-----END CERTIFICATE-----\n'
