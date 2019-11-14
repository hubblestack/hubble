# -*- encoding: utf-8 -*-
"""
Flexible Data Gathering: cert_discovery
=============================
Intention -
This fdg module allows connecting to open ports on a system and retrieving
certificate details that might be attached on those ports.

Testing -
    1. Configure this module through Hubble's schedule using the following configuration
       fdg_cert_discovery:
         function: fdg.fdg
         seconds: __seconds__
         splay: __splay__
         returner: __returner__
         run_on_start: __run_on_start__
         args:
           - <path to fdg profile>
    Make sure that cert_discovery.fdg profile exists and contains Osquery as the first
    module and this module as the second module.
    2. Alternately, execute hubble fdg.fdg <path to fdg profile> to run this module via cmd.
"""
import OpenSSL
import ssl
from socket import setdefaulttimeout
import logging
from datetime import datetime
log = logging.getLogger(__name__)

setdefaulttimeout(3)

def _get_certificate_san(x509cert):
    san = ''
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = ext.__str__()
    san_list = san.split(',')
    trimmed_san_list = []
    for san in san_list:
        trimmed_san = san.lstrip()
        trimmed_san_list.append(trimmed_san)
    return trimmed_san_list

def _load_certificate(ip, port):
    """
    fetch server certificate details and return Json with the first value being the
    status of ssl.get_server_certificate function and second value being the actual
    certificate data.
    """
    try:
        log.debug("FDG's cert_discovery is checking for ssl cert on {0}:{1}".format(ip,port))
        hostport = (str(ip), int(port))
        cert_details = ssl.get_server_certificate(hostport)
    except Exception as e:
        message = "FDG's cert_discovery Couldn't get cert: {0}".format(e)
        log.error(message)
        return {'result':False,'data':message}
    else:
        return {'result':True,'data':cert_details}

def _parse_cert(cert, host, port):
    """
    load the certificate using OpenSSL and parse needed params.
    """
    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert['data'])
        cert_details = {}
        cert_details['dest_port'] = str(port)
        cert_details['dest_ip'] = str(host)
        if x509.get_issuer():
            issuer_components = _format_components(x509.get_issuer())
            cert_details['issuer'] = issuer_components.get('CN', "None")
        if x509.get_subject():
            subject_components = _format_components(x509.get_subject())
            cert_details['country_name'] = subject_components.get('C', "None")
            cert_details['organisation_name'] = subject_components.get('O', "None")
            cert_details['organisation_unit_name'] = subject_components.get('OU', "None")
            cert_details['common_name'] = subject_components.get('CN', "None")
        not_after = datetime.strptime(x509.get_notAfter().decode('utf-8'), "%Y%m%d%H%M%SZ")
        not_before = datetime.strptime(x509.get_notBefore().decode('utf-8'), "%Y%m%d%H%M%SZ")
        has_expired = x509.has_expired()
        cert_details['version'] = str(x509.get_version())
        cert_details['has_expired'] = True if has_expired == 1 else False
        cert_details['serial_number'] = str(x509.get_serial_number())
        cert_details['expiry_date'] = str(not_after)
        cert_details['issue_date'] = str(not_before)
        cert_details['signature_algo'] = str(x509.get_signature_algorithm())
        cert_details['pem_cert'] = str(cert['data'])
        cert_details['SAN'] = _get_certificate_san(x509)
    except Exception as e:
        cert_details['error'] = "some error occurred while parsing certificate - {0}".format(e)
    return cert_details

def _fill_na(host, port, message):
    """
    Fill 'NA' in case of 'no cert found' on the input port.
    """
    cert_details = {}
    cert_details['country_name'] = 'NA'
    cert_details['organisation_name'] = 'NA'
    cert_details['organisation_unit_name'] = 'NA'
    cert_details['common_name'] = 'NA'
    cert_details['version'] = 'NA'
    cert_details['has_expired'] = 'NA'
    cert_details['serial_number'] = 'NA'
    cert_details['issuer'] = 'NA'
    cert_details['expiry_date'] = 'NA'
    cert_details['issue_date'] = 'NA'
    cert_details['signature_algo'] = 'NA'
    cert_details['pem_cert'] = 'NA'
    cert_details['dest_port'] = str(port)
    cert_details['error'] = message
    cert_details['dest_ip'] = str(host)

    return cert_details

def get_cert_details(host_ip='', host_port='', chained=None, chained_status=None):
    """
    This module is used to fetch certificate details on a host and port.
    This module can also be used in conjunction with osquery as the first module
    in the chain. Given that osquery fetches information about the open
    ports on a system and provides a 'host, port' tuple (or a list of host, port tuples)
    to this module, this module will connect to the host and port and fetch
    certificate details if a certificate is attached on the port. As an example,
    Osquery needs to provide the value of 'chained' in the following format.
    +-------------------------------+-----------+
    | host_ip                       | host_port |
    +-------------------------------+-----------+
    | 127.0.0.1                     | 80        |
    | 2001:db8:85a3::8a2e:370:7334  | 80        |
    | 127.0.0.1                     | 443       |
    | 2001:db8:85a3::8a2e:370:7334  | 443       |
    +-------------------------------+-----------+
    The first return value (status) will be True if the module is able to
        1. Connect to the port and fetch certificate details.
        2. Connect to the port and exit if no certificate is attached on the port.
    The first return value (status) will be False if the module encounters some
    exception in python's ssl.get_server_certificate function.

    chained
        The value chained from the previous call.

    chained_status
        The status returned by the chained call.
    """
    if host_ip == "":
        host = str(chained.get('host_ip', ''))
    else:
        host = str(host_ip.get('host_ip', ''))
    if host_port == "":
        port = int(chained.get('host_port', -1))
    else:
        port = int(host_port.get('host_port', -1))

    valid_inputs = _check_input_validity(host, port)
    if valid_inputs:
        cert = _load_certificate(host, port)
    else:
        message = "FDG's cert_discovery - invalid inputs"
        log.error(message)
        return False, ''
  
    if not cert:
        message = "FDG's cert_discovery - something went wrong while fetching cert"
        log.error(message)
        return False, ''

    if 'result' in cert.keys() and not cert.get('result'):
        message = "FDG's cert_discovery - no certificate found."
        log.info(message)
        cert_details = _fill_na(host, port, message)
    else:
        log.info("FDG's cert_discovery - cert found, parsing certificate")
        cert_details = _parse_cert(cert, host, port)
    return True, cert_details
    

def _check_input_validity(host, port):
    if host == '' or port == -1:
        return False
    if host.__contains__(" "):
        return False
    return True

def _format_components(x509name):
    items = {}
    for item in x509name.get_components():
        items[item[0]] = item[1]
    return items;

