import OpenSSL
import ssl
from socket import setdefaulttimeout
import logging
from datetime import datetime
LOG = logging.getLogger(__name__)

setdefaulttimeout(3)

def load_certificate(ip, port):
    try:
        LOG.info("checking for ssl cert on {0}:{1}".format(ip,port))
        hostport = (ip, port)
        c = ssl.get_server_certificate(hostport)
    except Exception as e:
        message = "Couldn't get cert: {0}".format(e)
        LOG.info(message)
        return {'result':False,'data':message}
    else:
        return {'result':True,'data':c}

def parse_cert(cert, port):
    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert['data'])
        cert_details = {}
        cert_details['port'] = port
        if x509.get_issuer():
            issuer_components = format_components(x509.get_issuer())
            cert_details['issuer'] = issuer_components.get('CN', "None")
        if x509.get_subject():
            subject_components = format_components(x509.get_subject())
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
    except Exception as e:
        cert_details['error'] = "some error occurred while parsing certificate - {0}".format(e)
    return cert_details

def fill_na(port, message):

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
    cert_details['port'] = port
    cert_details['error'] = message

    return cert_details

def get_cert_details(format_chained=True, chained=None, chained_status=None):
    hostname = chained['host_port']
    host, port = get_hostport(hostname)
    cert = load_certificate(host, port)
    if not cert['result']:
        message = "cert details not found"
        LOG.info(message)
        cert_details = fill_na(port, message)
    else:
        LOG.info('cert found, parsing certificate')
        cert_details = parse_cert(cert, port)
    return True, cert_details


def format_components(x509name):
    items = {}
    for item in x509name.get_components():
        items[item[0]] = item[1]
    return items;

def get_hostport(host_port):
    host = host_port.split(":")
    hostname = host[0]
    port = 443
    if len(host) == 2:
        port = int(host[1])
    return hostname, port

