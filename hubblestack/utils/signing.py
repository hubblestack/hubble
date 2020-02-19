# coding: utf-8
"""
hubblestack/utils/signing.py is a collection of tools that facility repo
signing and verification.

The settings for the signing and verification (and their defaults) are as
follows.

    repo_signing:
        # defaults
        require_verify: false
        ca_crt: /etc/hubble/sign/ca-root.crt
        public_crt: /etc/hubble/sign/public.crt
        private_key: /etc/hubble/sign/private.key

        # alternatively, ca_crt can be a list
        ca_crt:
          # there should be exactly one trusted cert
          # (only the first cert found in this file will count)
          - /etc/hubble/sign/ca-root.crt
          # all additional entries in the list (and all certs in each file)
          # will be included as untrusted certs; wqich (if a path can be found
          # to the root) may become trusted before verification. Normally these
          # would be intermediate or chain certs.
          - /etc/hubble/sign/untrusted.crt

For verification purposes, only the ca_crt and the public_crt are required. The
private key is only used for actually signing repos.

Signing can be accomplished with shell scripting and openssl packages. Only the
MANIFEST file is signed (contained in the SIGNATURE file). The MANIFEST is
simply a list of files preceeded by a SHA-256 hash digest.

To sign a repo simply (without having to write shell scripts, etc), issue
something like the following in a repo root.

    hubble signing.msign ./sign.this.file ./and-this-dir/
"""

import os
import logging
import re
import json
import io as cStringIO

from time import time
from collections import OrderedDict, namedtuple

# In any case, pycrypto won't do the job. The below requires pycryptodome.
# (M2Crypto is the other choice; but the docs are weaker, mostly non-existent.)

from Crypto.IO import PEM
from Crypto.Hash import SHA256

import OpenSSL.crypto as ossl

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

MANIFEST_RE = re.compile(r'^\s*(?P<digest>[0-9a-fA-F]+)\s+(?P<fname>.+)$')
log = logging.getLogger(__name__)

# "verification_log_timestamps" is a global dict that contains str path 
# and time() kv pairs. When the time() value exceeds the dampening_limit (3600 sec), 
# we reset time and set log level accordingly.
verif_log_timestamps = {}
# How often in seconds to set log level to log.error/critical
# maybe set in /etc/hubble/hubble
verif_log_dampener_lim = 120


def check_verif_timestamp(target):
    '''This function writes/updates a timestamp cache
    file for profiles
    Args:
        target -- string path of target file
    Expected Output:
        Bool -- True if the timestamp value of a profile is greater than or equal to
                the verif_log_dampener_lim, or if it is the first time a profile
                has been flagged
            -- False if it isn't greater than or equal to when the time() value of
                verif_log_timestamps
    '''
    global verif_log_timestamps
    global verif_log_dampener_lim


    # get the timestamp of the last time a profile failed a verification check
    ts_0 = verif_log_timestamps.get(target)
    if ts_0 is None:
        ts_0 = time()
        verif_log_timestamps[target] = ts_0
        return True

    ts_1 = time()
    # make a timedelta from the loaded timestamp vs now.
    td =  ts_1 - ts_0
    if td >= verif_log_dampener_lim:
        new_ts = time()
        verif_log_timestamps[target] = new_ts
        return True
    else:
        return False


class STATUS:
    """ container for status code (strings) """
    FAIL = 'fail'
    VERIFIED = 'verified'
    UNKNOWN = 'unknown'


class Options(object):
    """
    The Options class is simply a convenience interface for interacting with repo_signing options.

    Instead of `__salt__['config.get']('repo_signing:public_crt')`, write `Options.public_crt`.
    """
    class Defaults:
        """ defaults storage for options """
        require_verify = False
        ca_crt = '/etc/hubble/sign/ca-root.crt'
        public_crt = '/etc/hubble/sign/public.crt'
        private_key = '/etc/hubble/sign/private.key'

    def __getattribute__(self, name):
        """ If the option exists in the default pseudo meta class
            Try to find the option with config.get under repo_signing.
            Failing that, return the default from the pseudo meta class.
            If the option name isn't in the defaults, raise the exception.
        """
        try:
            return object.__getattribute__(self, name)
        except AttributeError:
            pass
        try:
            default = getattr(self.Defaults, name)
            return __salt__['config.get']('repo_signing:{}'.format(name), default)
      # except NameError:
      #     # __salt__ isn't defined: return the default?
      #     # should we just raise an exception cuz this was called too early??
      #     return default
        except AttributeError:
            raise

# replace class with instance
Options = Options() # pylint: disable=invalid-name ; this is fine

def split_certs(fh):
    """ attempt to split certs found in given filehandle into separate openssl cert objects

        returns a generator, for list, use `list(split_cerst(fh))`
    """

    ret = None
    for line in fh.readlines():
        if ret is None:
            if line.startswith('----'):
                ret = line
        else:
            ret += line
            if line.startswith('----'):
                ret = ret.encode()
                try:
                    yield ossl.load_certificate(ossl.FILETYPE_PEM, ret)
                except Exception as exception_object:
                    log.debug('decoding item as certificate failed: %s; trying as PEM encoded private key',
                        exception_object)
                    yield load_pem_private_key(ret, password=None, backend=default_backend())
                ret = None

def read_certs(*fnames):
    """ given a list of filenames (as varargs), attempt to find all certs in all named files.

        returns openssl objects as a generator.
        for a list: `list(read_certs('filename1', 'filename2'))`
    """
    for fname in fnames:
        if fname.strip().startswith('--') and '\x0a' in fname:
            for i in split_certs(cStringIO.StringIO(fname)):
                yield i
        elif os.path.isfile(fname):
            try:
                with open(fname, 'r') as fh:
                    for i in split_certs(fh):
                        yield i
            except Exception as exception_object:
                if check_verif_timestamp(fname) == True:
                    log.error('error while reading "%s": %s', fname, exception_object)

class X509AwareCertBucket:
    """
    A wrapper around the various operations required to verify certificate authenticity.

    We assume the `Options.ca_crt` is correct. We can check that the signature
    is valid, that the signature was generated by the given public.crt and that
    the public.crt is signed by the ca.crt.
    """
    PublicCertObj = namedtuple('PublicCertObj', ['crt', 'txt', 'status'])
    public_crt = tuple()

    def authenticate_cert(self):
        if any( i.status == STATUS.FAIL for i in self.public_crt ):
            return STATUS.FAIL
        if all( i.status == STATUS.VERIFIED for i in self.public_crt ):
            return STATUS.VERIFIED
        return STATUS.UNKNOWN

    def __init__(self, public_crt, ca_crt):
        try:
            import hubblestack.pre_packaged_certificates as HPPC
            # iff we have hardcoded certs then we're meant to ignore any other
            # configured value
            if hasattr(HPPC, 'public_crt'):
                log.debug('using pre-packaged-public_crt')
                public_crt = HPPC.public_crt
            if hasattr(HPPC, 'ca_crt'):
                log.debug('using pre-packaged-ca_crt')
                ca_crt = HPPC.ca_crt
        except ImportError:
            pass

        if isinstance(ca_crt, (list, tuple)):
            untrusted_crt = ca_crt[1:]
            ca_crt = ca_crt[0]
        else:
            untrusted_crt = list()

        if not isinstance(public_crt, (list, tuple)):
            public_crt = [ public_crt ]

        self.store = ossl.X509Store()
        self.trusted = list()
        # NOTE: trusted is mostly useless. We do use it in
        # testing, and that's probably about it

        already = set()
        for i in read_certs(ca_crt):
            digest = i.digest('sha1')
            if digest in already:
                continue
            already.add(digest)
            digest = digest.decode() + " " + stringify_ossl_cert(i)
            log.debug('adding {} as a trusted certificate approver'.format(digest))
            self.store.add_cert(i)
            self.trusted.append(digest)

        for i in read_certs(*untrusted_crt):
            digest = i.digest('sha1')
            if digest in already:
                continue
            already.add(digest)
            digest = digest.decode() + " " + stringify_ossl_cert(i)
            log.debug('checking to see if {} is trustworthy'.format(digest))
            try:
                ossl.X509StoreContext(self.store, i).verify_certificate()
                self.store.add_cert(i)
                self.trusted.append(digest)
                log.debug('added {} to verify store'.format(digest))
            except ossl.X509StoreContextError as exception_object:
                # log at either log.error or log.critical according to the error code
                log.critical('{}  not trustworthy: {}'.format(digest, exception_object))

        self.public_crt = list()
        for i in read_certs(*public_crt):
            status = STATUS.FAIL
            digest = i.digest('sha1')
            if digest in already:
                continue
            already.add(digest)
            digest = digest.decode() + " " + stringify_ossl_cert(i)
            log_level = log.debug
            log_level('checking to see if {} is a valid leaf cert'.format(digest))
            try:
                ossl.X509StoreContext(self.store, i).verify_certificate()
                status = STATUS.VERIFIED
                self.trusted.append(digest)
                log_level('marking {} verified'.format(digest))
            except ossl.X509StoreContextError as exception_object:
                code, depth, message = exception_object.args[0]
                if code in (2,3,20,27,33):
                    # from openssl/x509_vfy.h or 
                    # https://www.openssl.org/docs/man1.1.0/man3/X509_STORE_CTX_set_current_cert.html
                    # define X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT         2
                    #   the issuer certificate could not be found: 
                    #   this occurs if the issuer certificate of an 
                    #   untrusted certificate cannot be found.
                    # define X509_V_ERR_UNABLE_TO_GET_CRL                 3
                    #   the CRL of a certificate could not be found.
                    # define X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY 20
                    #   the issuer certificate of a locally looked up 
                    #   certificate could not be found. This normally means 
                    #   the list of trusted certificates is not complete.
                    # define X509_V_ERR_CERT_UNTRUSTED                    27
                    #   the root CA is not marked as trusted for the 
                    #   specified purpose.
                    # define X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER          33
                    #   the CRL of a certificate could not be found.
                    #   we just don't have the required info, it's not 
                    #   failing to verify not exactly, but it's definitely 
                    #   not verified either
                    status = STATUS.UNKNOWN
                if code in (10,12):
                    # define X509_V_ERR_CERT_HAS_EXPIRED                  10
                    #   the certificate has expired: that is the not
                    #   After date is before the current time.
                    # define X509_V_ERR_CRL_HAS_EXPIRED                   12
                    #   the CRL has expired.
                    status = STATUS.FAIL
                # log at either log.error or log.critical according to the error code
                if status == STATUS.FAIL and check_verif_timestamp(vfname) == True:
                    log_level = log.critical
                elif status == STATUS.ERROR and check_verif_timestamp(vfname) == True:
                    log_level = log.error
                msg = 'cert: "{}" | status: "{}"| error code: {} | depth: {} |message: {}'
                log_level(msg.format(digest, status, code, depth, message))

            self.public_crt.append(self.PublicCertObj(i, digest, status))


def stringify_ossl_cert(a_cert_obj):
    """ try to stryingy a cert object into its subject components and digest hexification.

        E.g. (with extra newline added for line-wrap):
            3E:9C:58:F5:27:89:A8:F4:B7:AB:4D:1C:56:C8:4E:F0:03:0F:C8:C3
            C=US/ST=State/L=City/O=Org/OU=Group/CN=Certy Cert #1
    """
    if isinstance(a_cert_obj, (list,tuple)):
        return ', '.join([ stringify_ossl_cert(i) for i in a_cert_obj ])
    return '/'.join([ '='.join([ j.decode() for j in i ]) for i in a_cert_obj.get_subject().get_components() ])

def jsonify(obj, indent=2):
    """ cury function to add default indent=2 to json.dumps(obj, indent=indent) """
    return json.dumps(obj, indent=indent)

def normalize_path(path, trunc=None):
    """ attempt to translate /home/./jettero////files/.bashrc
        to /home/jettero/files/.bashrc; optionally truncating
        the path if it starts with the given trunc kwarg string.
    """
    norm = os.path.normpath(path)
    if trunc:
        if norm.startswith(os.path.sep + trunc + os.path.sep):
            norm = norm[len(trunc)+2:]
        elif norm.startswith(trunc + os.path.sep):
            norm = norm[len(trunc)+1:]
        elif norm.startswith(os.path.sep + trunc):
            norm = norm[len(trunc)+1:]
        elif norm.startswith(trunc):
            norm = norm[len(trunc):]
    # log.debug("normalize_path(%s) --> %s", path, norm)
    return norm

def hash_target(fname, obj_mode=False, chosen_hash=None):
    """ read in a file (fname) and either return the hex digest
        (obj_mode=False) or a sha256 object pre-populated with the contents of
        the file.
    """
    if chosen_hash is None:
        chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash, default_backend())
    if os.path.isfile(fname):
        with open(fname, 'rb') as fh:
            buffer = fh.read(1024)
            while buffer:
                hasher.update(buffer)
                buffer = fh.read(1024)
    if obj_mode:
        return hasher, chosen_hash
    digest = hasher.finalize()
    hex_digest = ''.join([ '{:02x}'.format(ord(i)) for i in digest ])
    log.debug('hashed %s: %s', fname, hex_digest)
    return hex_digest

def descend_targets(targets, callback):
    """
    recurse into the given `targets` (files or directories) and invoke the `callback`
    callback on each file found.
    """
    for fname in targets:
        if os.path.isfile(fname):
            callback(fname)
        if os.path.isdir(fname):
            for dirpath, dirnames, filenames in os.walk(fname):
                for fname in filenames:
                    fname_ = os.path.join(dirpath, fname)
                    callback(fname_)

def manifest(targets, mfname='MANIFEST'):
    """
    Produce a manifest file given `targets`.
    """
    with open(mfname, 'w') as mfh:
        def append_hash(fname):
            fname = normalize_path(fname)
            digest = hash_target(fname)
            mfh.write('{} {}\n'.format(digest, fname))
            log.debug('wrote %s %s to %s', digest, fname, mfname)
        descend_targets(targets, append_hash)

def sign_target(fname, ofname, private_key='private.key', **kwargs): # pylint: disable=unused-argument
    """
    Sign a given `fname` and write the signature to `ofname`.
    """
    # NOTE: This is intended to crash if there's some number of keys other than
    # exactly 1 read from the private_key file:
    first_key, = read_certs(private_key)
    hasher, chosen_hash = hash_target(fname, obj_mode=True)
    args = { 'data': hasher.finalize() }
    if isinstance(first_key, rsa.RSAPrivateKey):
        args['padding'] = padding.PSS( mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH)
        args['algorithm'] = utils.Prehashed(chosen_hash)
    sig = first_key.sign(**args)
    with open(ofname, 'w') as fh:
        log.debug('writing signature of %s to %s', os.path.abspath(fname), os.path.abspath(ofname))
        fh.write(PEM.encode(sig, 'Detached Signature of {}'.format(fname)))
        fh.write('\n')

def verify_signature(fname, sfname, public_crt='public.crt', ca_crt='ca-root.crt', **kwargs): # pylint: disable=unused-argument
    """
        Given the fname, sfname public_crt and ca_crt:

        return STATUS.FAIL if the signature doesn't match
        return STATUS.UNKNOWN if the certificate signature can't be verified with the ca cert
        return STATUS.VERIFIED if both the signature and the CA sig match
    """
    log.debug('verify_signature(fname="{}", sfname="{}", public_crt="{}", ca_crt="{}"'.format(
        fname, sfname, public_crt, ca_crt))
    try:
        with open(sfname, 'r') as fh:
            sig,_,_ = PEM.decode(fh.read()) # also returns header and decrypted-status
    except IOError:
        log.info('verify_signature() failed to find sfname="{}" for fname="{}"'.format(
            sfname, fname))
        return STATUS.UNKNOWN
    x509 = X509AwareCertBucket(public_crt, ca_crt)
    hasher, chosen_hash = hash_target(fname, obj_mode=True)
    digest = hasher.finalize()
    args = { 'signature': sig, 'data': digest }
    for crt,txt,status in x509.public_crt:
        log_level = log.debug
        log_level('trying to check "{}" with "{}"'.format( sfname, txt))
        pubkey = crt.get_pubkey().to_cryptography_key()
        if isinstance(pubkey, rsa.RSAPublicKey):
            args['padding'] = padding.PSS( mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH)
            args['algorithm'] = utils.Prehashed(chosen_hash)
        try:
            pubkey.verify(**args)
            return status
        except InvalidSignature:
            if check_verif_timestamp(sfname) == True:
                log_level = log.critical
            log_level('public verification status: "{}" | cert text: "{}" |'.format(
                STATUS.FAIL, txt ))
            pass
    return STATUS.FAIL


def iterate_manifest(mfname):
    """
    Generate an interator from the MANFIEST file. Each iter item is a filename
    (not the digest portion of the line).
    """
    with open(mfname, 'r') as fh:
        for line in fh.readlines():
            matched = MANIFEST_RE.match(line)
            if matched:
                _,manifested_fname = matched.groups()
                manifested_fname = normalize_path(manifested_fname)
                yield manifested_fname


def verify_files(targets, mfname='MANIFEST', sfname='SIGNATURE', public_crt='public.crt', ca_crt='ca-root.crt'):
    """ given a list of `targets`, a MANIFEST, and a SIGNATURE file:

        1. Check the signature of the manifest, mark the 'MANIFEST' item of the return as:
             STATUS.FAIL if the signature doesn't match
             STATUS.UNKNOWN if the certificate signature can't be verified with the ca cert
             STATUS.VERIFIED if both the signature and the CA sig match
        2. mark all targets as STATUS.UNKNOWN
        3. check the digest of each target against the manifest, mark each file as
             STATUS.FAIL if the digest doesn't match
             STATUS.*, the status of the MANIFEST file above

        return a mapping from the input target list to the status values (a dict of filename: status)
    """
    log.debug("verify_files({}, mfname={}, sfname={}, public_crt={}, ca_crt={}".format(
        targets, mfname, sfname, public_crt, ca_crt))
    ret = OrderedDict()
    ret[mfname] = verify_signature(mfname, sfname=sfname, public_crt=public_crt, ca_crt=ca_crt)
    # ret[mfname] is the strongest claim we can make about the files we're
    # verifiying if they match their hash in the manifest, the best we can say
    # is whatever is the status of the manifest iteslf.

    mf_dir, _ = os.path.split(mfname)
    sf_dir, _ = os.path.split(sfname)

    if mf_dir and mf_dir == sf_dir:
        trunc = mf_dir + '/'
    else:
        trunc = None

    # prepopulate digests with STATUS.UNKNOWN, skip things that shouldn't be
    # digested (MANIFEST, SIGNATURE, etc) and build a database mapping
    # normalized names back to given target names.
    xlate = dict()
    digests = OrderedDict()
    if not targets:
        targets = list(iterate_manifest(mfname))
    for otarget in targets:
        target = normalize_path(otarget, trunc=trunc)

        log.debug('found manifest for {} ({})'.format(otarget, target))
        if otarget != target:
            xlate[target] = otarget
        if target in digests or target in (mfname, sfname):
            continue
        digests[target] = STATUS.UNKNOWN
    # populate digests with the hashes from the MANIFEST
    if os.path.isfile(mfname):
        with open(mfname, 'r') as fh:
            for line in fh.readlines():
                matched = MANIFEST_RE.match(line)
                if matched:
                    digest,manifested_fname = matched.groups()
                    manifested_fname = normalize_path(manifested_fname)
                    if manifested_fname in digests:
                        digests[manifested_fname] = digest
    # number of seconds before a FAIL or UNKNOWN is set to the returner
    global verif_log_timestamps
    # compare actual digests of files (if they exist) to the manifested digests
    for vfname in digests:
        digest = digests[vfname]
        htname = os.path.join(trunc, vfname) if trunc else vfname
        new_hash = hash_target(htname)

        log_level = log.debug
        if digest == STATUS.UNKNOWN:
            # digests[vfname] is either UNKNOWN (from the targets population)
            # or it's a digest from the MANIFEST. If UNKNOWN, we have nothing to compare
            # so we return UNKNOWN
            status = STATUS.UNKNOWN
            # check to see if the the status of a failed target has been sent is the last 
            # x seconds, we reset time and set log level accordingly. the same for FAIL
            # if check_verif_timestamp(vfname) == True:
            #    log_level = log.error
        elif digest == new_hash:
            # path gets same status as MANIFEST
            # Cool, the digest matches, but rather than mark STATUS.VERIFIED,
            # we mark it with the same status as the MANIFEST itself --
            # presumably it's signed (STATUS.VERIFIED); but perhaps it's only
            # UNKNOWN or even FAIL.
            status = ret[mfname]
        else:
            # We do have a MANIFEST entry and it doesn't match: FAIL with or
            # without a matching SIGNATURE
            status = STATUS.FAIL
            #if check_verif_timestamp(vfname) == True:
            #     log_level = log.critical
        if status == STATUS.FAIL and check_verif_timestamp(vfname) == True:
            log_level = log.critical
        elif status == STATUS.UNKNOWN and check_verif_timestamp(vfname) == True:
            log_level = log.error
        # logs according to the STATUS of target file
        msg = 'verification status: "{}" for "{}" | manifest sha256: "{}" | real sha256: "{}"'
        log_level(msg.format(status, vfname, digest, new_hash))
        ret[vfname] = status

    # fix any normalized names so the caller gets back their specified targets
    for k,v in xlate.items():
        ret[v] = ret.pop(k)
    return ret


#### wrappers:
def find_wrapf(not_found={'path': '', 'rel': ''}, real_path='path'):
    """
    Wrap a filesystem find_file function and return the original result if the
    MANIFEST and SIGNATURE indicate the file is valid. If the file is not verified
    and Options.require_verify is False (the default); but the file did not
    explicity fail to match the MANIFEST, continue to return the original find result.

    Otherwise, return a pretend not-found result instead of the original repo result.
    """
    def wrapper(find_file_f):
        def _p(fnd):
            return fnd.get(real_path, fnd.get('path', ''))

        def inner(path, saltenv, *a, **kwargs):
            f_mani = find_file_f('MANIFEST', saltenv, *a, **kwargs )
            f_sign = find_file_f('SIGNATURE', saltenv, *a, **kwargs )
            f_path = find_file_f(path, saltenv, *a, **kwargs)
            real_path = _p(f_path)
            mani_path = _p(f_mani)
            sign_path = _p(f_sign)
            log.debug('path={}, rpath={}, manifest={}, signature={}'.format(
                path, real_path, mani_path, sign_path))
            if not real_path:
                return f_path
            verify_res = verify_files([real_path],
                mfname=mani_path, sfname=sign_path,
                public_crt=Options.public_crt, ca_crt=Options.ca_crt)
            log.debug('verify: %s', dict(**verify_res))
            vrg = verify_res.get(real_path, STATUS.UNKNOWN)
            if vrg == STATUS.VERIFIED:
                return f_path
            if vrg == STATUS.UNKNOWN and not Options.require_verify:
                return f_path
            log.debug('claiming not found')
            return dict(**not_found)
        return inner
    return wrapper
