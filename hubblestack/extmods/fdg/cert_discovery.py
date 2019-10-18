import OpenSSL
import ssl
from socket import *
import logging
from datetime import datetime
import sys
import json
logger = logging.getLogger(__name__)

setdefaulttimeout(3)

def load_certificate(ip, port):
    try:
        logger.info("checking for ssl cert on {0}:{1}".format(ip,port))
        hostport = (ip, port)
        c = ssl.get_server_certificate(hostport)
    except Exception as e:
        message = "Couldn't get cert: {0}".format(e)
        logger.info(message)
        return {'result':False,'data':message}
    else:
        return {'result':True,'data':c}

def get_cert_details(format_chained=True, chained=None, chained_status=None):
    hostname = chained['host_port']
    print(hostname)
    host, port = get_hostport(hostname)
    print(host)
    print(port)
    cert = load_certificate(host, port)
    if not cert['result']:
        print("result was false")
        return True, "cert not found"
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert['data'])
    issuer_components = format_components(x509.get_issuer())
    issuer = issuer_components.get('CN', "None")

    not_after = datetime.strptime(x509.get_notAfter().decode('utf-8'),
                                  "%Y%m%d%H%M%SZ")
    not_before = datetime.strptime(x509.get_notBefore().decode('utf-8'),
                                   "%Y%m%d%H%M%SZ")

    subject_components = format_components(x509.get_subject())
    country_name = subject_components.get('C', "None")
    organisation_name = subject_components.get('O', "None")
    organisation_unit_name = subject_components.get('OU', "None")
    common_name = subject_components.get('CN', "None")
    version = x509.get_version()
    has_expired = x509.has_expired()
    serial_number = x509.get_serial_number()
    signature_algo = x509.get_signature_algorithm()

    cert_details = {}
    cert_details['country_name'] = country_name
    cert_details['organisation_name'] = organisation_name
    cert_details['organisation_unit_name'] = organisation_unit_name
    cert_details['common_name'] = common_name
    cert_details['version'] = str(version)
    cert_details['has_expired'] = True if has_expired == 1 else False
    cert_details['serial_number'] = str(serial_number)
    cert_details['issuer'] = issuer
    cert_details['expiry_date'] = str(not_after)
    cert_details['issue_date'] = str(not_before)
    cert_details['signature_algo'] = str(signature_algo)
    cert_details['pem_cert'] = str(cert['data'])
    cert_details['port'] = port

    return True, cert_details


def format_components(x509name):
    items = {}
    for item in x509name.get_components():
        items[item[0]] = item[1]
        # items.append('%s=%s' %  (item[0], item[1]) )
    return items;

def get_hostport(host_port):
    host = host_port.split(":")
    hostname = host[0]
    port = 443
    if len(host) == 2:
        port = int(host[1])
    return hostname, port

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Please specify host and port in host:port format")
    host = sys.argv[1].split(":")
    hostname = host[0]
    port = 443
    if len(host) == 2:
        port = int(host[1])
    cert_details = get_cert_details(hostname, port)
    print(cert_details)
