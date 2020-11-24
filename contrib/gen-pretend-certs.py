#!/usr/bin/env python
# coding: UTF-8

import six
import os
import shutil
import argparse
import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed448, ed25519
from cryptography.x509.oid import NameOID

DEFAULT_PDIR = '.pretend-certs'

def genkey(key_type='rsa', rsa_key_size=1024, rsa_public_exponent=65537, **args):
    if key_type == 'rsa':
        return rsa.generate_private_key(
            public_exponent=rsa_public_exponent,
            key_size=rsa_key_size, backend=default_backend())
    elif key_type == 'ed448':
        return ed448.Ed448PrivateKey.generate()
    elif key_type == 'ed25519':
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError('Unknown key_type={}'.format(key_type))

def as_pem(key):
    if isinstance(key, (rsa.RSAPrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey)):
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
    elif isinstance(key, (rsa.RSAPublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey)):
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    elif isinstance(key, x509.Certificate):
        return key.public_bytes(encoding=serialization.Encoding.PEM)
    raise ValueError('Unhandled key class {}'.format(type(key)))

class Authority:
    def __init__(self, key, crt):
        self.key = key
        self.crt = crt

def gen_CA(fname='ca-root', cn='ca-root', path_length=0, authority=None, pdir=DEFAULT_PDIR, **args):
    private_key = genkey(**args)
    public_key  = private_key.public_key()

    with open(os.path.join(pdir, fname + '.key'), 'wb') as fh:
        fh.write( as_pem(private_key) )

    with open(os.path.join(pdir, fname + '.unsigned'), 'wb') as fh:
        fh.write( as_pem(public_key) )

    ksec_100 = datetime.timedelta(0, 100e3, 0)
    Msec_300 = datetime.timedelta(0, 300e6, 0)

    builder = x509.CertificateBuilder()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'State'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'City'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Org'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'Group'),
        x509.NameAttribute(NameOID.COMMON_NAME, six.text_type(cn)),
    ])

    if authority:
        issuer = authority.crt.subject

    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.not_valid_before(datetime.datetime.today() - ksec_100)
    builder = builder.not_valid_after(datetime.datetime.today() + Msec_300)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)

    authority_public_key = authority.crt.public_key() if authority else public_key
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_public_key), critical=False
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
    )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=path_length), critical=True,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=False,
            key_agreement=False,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False,
        ), critical=True
    )

    signing_args = {
        'private_key': authority.key if authority else private_key,
        'backend': default_backend(),
        'algorithm': None,
    }

    if isinstance(signing_args['private_key'], rsa.RSAPrivateKey):
        signing_args['algorithm'] = hashes.SHA256()

    certificate = builder.sign(**signing_args)

    with open(os.path.join(pdir, fname + '.crt'), 'wb') as fh:
        fh.write( as_pem(certificate) )

    return Authority(private_key, certificate)

def gen_leaf(authority, fname_template='{}', cn='Certy Cert McCertFace', pdir=DEFAULT_PDIR, **args):
    private_key = genkey(**args)
    public_key  = private_key.public_key()

    private_name = fname_template.format('private')
    public_name = fname_template.format('public')

    with open(os.path.join(pdir, private_name + '.key'), 'wb') as fh:
        fh.write( as_pem(private_key) )

    with open(os.path.join(pdir, public_name + '.unsigned'), 'wb') as fh:
        fh.write( as_pem(public_key) )

    ksec_100 = datetime.timedelta(0, 100e3, 0)
    Msec_300 = datetime.timedelta(0, 300e6, 0)

    builder = x509.CertificateBuilder()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'State'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'City'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Org'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'Group'),
        x509.NameAttribute(NameOID.COMMON_NAME, six.text_type(cn)),
    ])

    builder = builder.subject_name(subject)
    builder = builder.issuer_name(authority.crt.subject)
    builder = builder.not_valid_before(datetime.datetime.today() - ksec_100)
    builder = builder.not_valid_after(datetime.datetime.today() + Msec_300)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)

    authority_public_key = authority.crt.public_key()
    # this would pin us to exactly one issuer; without it, any matching issuer
    # CN should do the trick
    # builder = builder.add_extension(
    #     x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_public_key), critical=False
    # )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            data_encipherment=True,
            content_commitment=True,
            key_cert_sign=False,
            crl_sign=False,
            key_agreement=False,
            key_encipherment=False,
            encipher_only=False,
            decipher_only=False,
        ), critical=True
    )

    signing_args = {
        'private_key': authority.key,
        'backend': default_backend(),
        'algorithm': None,
    }

    if isinstance(signing_args['private_key'], rsa.RSAPrivateKey):
        signing_args['algorithm'] = hashes.SHA256()

    certificate = builder.sign(**signing_args)

    with open(os.path.join(pdir, public_name + '.crt'), 'wb') as fh:
        fh.write( as_pem(certificate) )

    return Authority(private_key, certificate)

def main(root_cn, int1_cn, int2_cn, **args):
    if os.path.isdir(args['pdir']):
        shutil.rmtree(args['pdir'])
    os.mkdir(args['pdir'])

    ca  = gen_CA(cn=root_cn, fname='ca-root', path_length=1, **args)
    ia1 = gen_CA(cn=int1_cn, fname='intermediate-1', authority=ca, path_length=0, **args)
    ia2 = gen_CA(cn=int2_cn, fname='intermediate-2', authority=ca, path_length=0, **args)

    lf1 = gen_leaf(cn='Certy Cert #1', fname_template='{}-1', authority=ia1, **args)
    lf2 = gen_leaf(cn='Certy Cert #2', fname_template='{}-2', authority=ia2, **args)

    with open(os.path.join(args['pdir'], 'bundle.pem'), 'wb') as ofh:
        for i in range(1,3):
            with open(os.path.join(args['pdir'], 'intermediate-{}.crt'.format(i)), 'rb') as ifh:
                ofh.write(ifh.read())

if __name__ == '__main__':
    parser = argparse.ArgumentParser( # description='this program',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-o', '--output-dir', dest='pdir', type=str, default=DEFAULT_PDIR)
    parser.add_argument('-R', '--root-cn', type=six.text_type, default='car.hubblestack.io')
    parser.add_argument('-I', '--int1-cn', type=six.text_type, default='ia1.hubblestack.io')
    parser.add_argument('-J', '--int2-cn', type=six.text_type, default='ia2.hubblestack.io')
    parser.add_argument('-t', '--key-type', type=six.text_type,
        choices=['rsa', 'ed448', 'ed25519'], default='rsa')
    parser.add_argument('-z', '--rsa-key-size', type=int, default=1024)
    parser.add_argument('-p', '--rsa-public-exponent', type=int, default=65537)

    args = parser.parse_args()

    try: main(**args.__dict__)
    except KeyboardInterrupt: pass
