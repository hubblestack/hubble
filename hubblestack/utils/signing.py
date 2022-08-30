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
import re
import io as cStringIO

from time import time
from collections import namedtuple

# In any case, pycrypto won't do the job. The below requires pycryptodome.
# (M2Crypto is the other choice; but the docs are weaker, mostly non-existent.)

import OpenSSL.crypto as ossl
import OpenSSL._util

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from hubblestack.utils.signing_helpers import (
    encode_pem,
    decode_pem,
    stringify_ossl_cert,
    normalize_path,
    run_callback,
    _cache_key,
    STATUS,
    Options,
    log,
)

MANIFEST_RE = re.compile(r"^\s*(?P<digest>[0-9a-fA-F]+)\s+(?P<fname>.+)$")


def _our_byte_string(x, charmap="utf-8"):  # pylint: disable=unused-argument
    # MONKEYPATCH OpenSSL._utils:byte_string to avoid "charmap" issues on POSIX
    # locale platforms
    return x.encode("utf-8")


OpenSSL._util.byte_string = _our_byte_string

# "verification_log_timestamps" is a global dict that contains str path
# and time() kv pairs. When the time() value exceeds the dampening_limit (3600 sec),
# we reset time and set log level accordingly.
VERIFY_LOG_TIMESTAMPS = {}
# How often in seconds 3600 = 1 hour to set log level to log.error/critical
# maybe set in /etc/hubble/hubble
VERIFY_LOG_DAMPENER_LIM = [3600]


def _format_padding_bits(x):
    if isinstance(x, (list, tuple)):
        x = x[0]
    if isinstance(x, str) and "max" in x.lower():
        return padding.PSS.MAX_LENGTH
    return int(x)


def _format_padding_bits_txt(x):
    if isinstance(x, (tuple, list)):
        return "/".join([_format_padding_bits_txt(y) for y in x])
    if x is padding.PSS.MAX_LENGTH:
        return "max"
    return str(x)


def check_is_ca(crt):
    """
    Verify `crt` is Certificate Authority
    """
    try:
        crt = crt.to_cryptography()
    except (TypeError, AttributeError):
        pass
    try:
        for e in crt.extensions:
            try:
                if e.value.ca:
                    return True
            except AttributeError:
                pass
    except AttributeError:
        pass
    return False


def check_verify_timestamp(target, dampener_limit=None):
    """This function writes/updates a timestamp cache
    file for profiles
    Args:
        target -- string path of target file
        dampener_limit -- wants the number of seconds integer before it updates
            verif_log_timestamps and returns True
    Expected Output:
        Bool -- True if the timestamp value of a profile is greater than or equal to
                the verif_log_dampener_lim, or if it is the first time a profile
                has been flagged
            -- False if it isn't greater than or equal to when the time() value of
                verif_log_timestamps
    """
    if dampener_limit is None:
        dampener_limit = VERIFY_LOG_DAMPENER_LIM[0]

    # get the ts of the last time a profile failed a verification check
    ts_0 = VERIFY_LOG_TIMESTAMPS.get(target)
    if ts_0 is None:
        ts_0 = time()
        VERIFY_LOG_TIMESTAMPS[target] = ts_0
        return True

    ts_1 = time()
    # make a timedelta from the loaded ts vs now.
    td = ts_1 - ts_0  # pylint: disable=invalid-name ; this is fine
    if td >= dampener_limit:
        new_ts = time()
        VERIFY_LOG_TIMESTAMPS[target] = new_ts
        return True
    return False


# replace class with instance
Options = Options()  # pylint: disable=invalid-name ; this is fine


def split_certs(fh):
    """attempt to split certs found in given filehandle into separate openssl cert objects

    returns a generator, for list, use `list(split_cerst(fh))`
    """

    ret = None
    short_fname = fh.name.split("/")[-1]
    for line in fh.readlines():
        if ret is None:
            if line.startswith("----"):
                ret = line
        else:
            ret += line
            if line.startswith("----"):
                ret = ret.encode()
                log_level = log.debug
                try:
                    yield ossl.load_certificate(ossl.FILETYPE_PEM, ret)
                except Exception as exception_object:
                    status = STATUS.UNKNOWN
                    if check_verify_timestamp(fh):
                        log_level = log.warning
                    log_level(
                        '%s: | file: "%s" | cert decoding status: %s | attempting as PEM encoded private key',
                        short_fname,
                        fh.name,
                        status,
                    )
                    yield load_pem_private_key(ret, password=None, backend=default_backend())
                ret = None


def read_certs(*fnames):
    """given a list of filenames (as varargs), attempt to find all certs in all named files.

    returns openssl objects as a generator.
    for a list: `list(read_certs('filename1', 'filename2'))`
    """
    for fname in fnames:
        if fname.strip().startswith("--") and "\x0a" in fname:
            siofh = cStringIO.StringIO(fname)
            siofh.name = "<a string>"
            for i in split_certs(siofh):
                i.source_filename = "<string>"
                yield i
        elif os.path.isfile(fname):
            try:
                with open(fname, "r") as fh:
                    for i in split_certs(fh):
                        i.source_filename = fname
                        yield i
            except Exception as exception_object:
                log_level = log.debug
                if check_verify_timestamp(fname):
                    log_level = log.error
                log_level('error while reading "%s": %s', fname, exception_object)


def stringify_cert_files(cert):
    """this function returns a string version of cert(s) for returner"""
    if isinstance(cert, (tuple, list)) and cert:
        return ", ".join([stringify_cert_files(c) for c in cert])
    elif hasattr(cert, "source_filename"):
        return cert.source_filename
    elif hasattr(cert, "name"):
        # probably a file handle
        return cert.name
    return str(cert)


class X509AwareCertBucket:
    """
    A wrapper around the various operations required to verify certificate authenticity.

    We assume the `Options.ca_crt` is correct. We can check that the signature
    is valid, that the signature was generated by the given public.crt and that
    the public.crt is signed by the ca.crt.
    """

    PublicCertObj = namedtuple("PublicCertObj", ["crt", "txt", "status"])
    public_crt = tuple()

    def authenticate_cert(self):
        if any(i.status == STATUS.FAIL for i in self.public_crt):
            return STATUS.FAIL
        if all(i.status == STATUS.VERIFIED for i in self.public_crt):
            return STATUS.VERIFIED
        return STATUS.UNKNOWN

    def __init__(self, public_crt=None, ca_crt=None, extra_crt=None):
        try:
            import hubblestack.pre_packaged_certificates as HPPC

            # iff we have hardcoded certs then we're meant to ignore any other
            # configured value
            if hasattr(HPPC, "public_crt"):
                log.debug("using pre-packaged-public_crt")
                public_crt = HPPC.public_crt
            if hasattr(HPPC, "ca_crt"):
                log.debug("using pre-packaged-ca_crt")
                ca_crt = HPPC.ca_crt
        except ImportError:
            pass

        if public_crt is None:
            public_crt = Options.public_crt

        if ca_crt is None:
            ca_crt = Options.ca_crt

        if isinstance(ca_crt, (list, tuple)):
            untrusted_crt = ca_crt[1:]
            ca_crt = ca_crt[0]
        else:
            untrusted_crt = list()

        if not isinstance(public_crt, (list, tuple)):
            public_crt = [public_crt]

        # load all the certs into cryptography objects
        ca_crt = list(read_certs(ca_crt))  # no *, only one
        untrusted_crt = list(read_certs(*untrusted_crt))
        public_crt = list(read_certs(*public_crt))

        # if there are extra_crts; try to parse them into intermediates and
        # signing certificates per their basicConstraints.ca header (if any)
        if extra_crt:
            if not isinstance(extra_crt, (list, tuple)):
                extra_crt = [extra_crt]
            for crt in read_certs(*extra_crt):
                if check_is_ca(crt):
                    untrusted_crt.append(crt)
                else:
                    public_crt.append(crt)

        # build a keyring
        self.store = ossl.X509Store()
        self.trusted = list()
        # NOTE: trusted is mostly useless. We do use it in
        # testing, and that's probably about it
        seconds_day = 86400
        already = set()
        for i in ca_crt:
            log_level = log.debug
            digest = i.digest("sha1")
            if digest in already:
                continue
            already.add(digest)
            digest = digest.decode() + " " + stringify_ossl_cert(i)
            self.store.add_cert(i)  # add cert to keyring as a trusted cert
            self.trusted.append(digest)
            log_level = log.debug
            if check_verify_timestamp(digest, dampener_limit=seconds_day):
                log_level = log.splunk
            status = STATUS.VERIFIED
            str_ca = stringify_cert_files(ca_crt)
            log_level(
                'ca cert | file: "%s" | status: %s | digest "%s" | added to verify store', str_ca, status, digest
            )

        for i in untrusted_crt:
            log_level = log.debug
            digest = i.digest("sha1")
            if digest in already:
                continue
            already.add(digest)
            digest = digest.decode() + " " + stringify_ossl_cert(i)
            try:
                ossl.X509StoreContext(self.store, i).verify_certificate()
                self.store.add_cert(i)  # add to trusted keyring
                self.trusted.append(digest)
                status = STATUS.VERIFIED
            except ossl.X509StoreContextError as exception_object:
                status = STATUS.FAIL
            if check_verify_timestamp(digest, dampener_limit=seconds_day):
                log_level = log.splunk
                if status == STATUS.FAIL:
                    log_level = log.error
                elif status == STATUS.UNKNOWN:
                    log_level = log.error
            str_untrusted = stringify_cert_files(untrusted_crt)
            log_level('intermediate certs | file: "%s" | status: %s | digest "%s"', str_untrusted, status, digest)

        self.public_crt = list()
        for i in public_crt:
            status = STATUS.FAIL
            digest = i.digest("sha1")
            if digest in already:
                continue
            already.add(digest)
            digest = digest.decode() + " " + stringify_ossl_cert(i)
            log_level = log.debug
            try:
                ossl.X509StoreContext(self.store, i).verify_certificate()
                status = STATUS.VERIFIED
                self.trusted.append(digest)
                if check_verify_timestamp(digest, dampener_limit=seconds_day):
                    log_level = log.splunk
                    if status == STATUS.FAIL:
                        log_level = log.error
                    elif status == STATUS.UNKNOWN:
                        log_level = log.error
                str_public = stringify_cert_files(public_crt)
                log_level('public cert | file: "%s" | status : "%s" | digest: "%s"', str_public, status, digest)
            except ossl.X509StoreContextError as exception_object:
                code, depth, message = exception_object.args[0]
                if code in (2, 3, 20, 27, 33):
                    # from openssl/x509_vfy.h or
                    # https://www.openssl.org/docs/man1.1.0/man3/X509_STORE_CTX_set_current_cert.html
                    # X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT         2
                    # X509_V_ERR_UNABLE_TO_GET_CRL                 3
                    # X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY 20
                    # X509_V_ERR_CERT_UNTRUSTED                    27
                    # X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER          33
                    status = STATUS.UNKNOWN
                if code in (10, 12):
                    # X509_V_ERR_CERT_HAS_EXPIRED                  10
                    # X509_V_ERR_CRL_HAS_EXPIRED                   12
                    status = STATUS.FAIL
                if check_verify_timestamp(digest, dampener_limit=seconds_day):
                    log_level = log.splunk
                    if status == STATUS.FAIL:
                        log_level = log.error
                    elif status == STATUS.UNKNOWN:
                        log_level = log.error
                str_public = stringify_cert_files(public_crt)
                log_level(
                    'public cert | file: "%s" | status: %s | digest: "%s" | X509 error code: %s | depth: %s | message: "%s"',
                    str_public,
                    status,
                    digest,
                    code,
                    depth,
                    message,
                )

            # add to list of keys we'll use to check signatures:
            self.public_crt.append(self.PublicCertObj(i, digest, status))


def hash_target(fname, obj_mode=False, chosen_hash=None):
    """read in a file (fname) and either return the hex digest
    (obj_mode=False) or a sha256 object pre-populated with the contents of
    the file.
    """
    if chosen_hash is None:
        chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash, default_backend())
    if os.path.isfile(fname):
        with open(fname, "rb") as fh:
            buffer = fh.read(1024)
            while buffer:
                hasher.update(buffer)
                buffer = fh.read(1024)
    if obj_mode:
        return hasher, chosen_hash
    digest = hasher.finalize()
    hex_digest = "".join(["{:02x}".format(i) for i in digest])
    log.debug("hashed %s: %s", fname, hex_digest)
    return hex_digest


def create_manifest(targets, mfname=None):
    """
    Produce a create_manifest file given `targets`.
    """

    if mfname is None:
        mfname = Options.manifest_file_name

    with open(mfname, "w") as mfh:

        def append_hash(fname):
            fname = normalize_path(fname)
            digest = hash_target(fname)
            mfh.write("{} {}\n".format(digest, fname))
            log.debug("wrote %s %s to %s", digest, fname, mfname)

        run_callback(targets, append_hash)


def sign_target(fname, ofname, private_key=None, **kwargs):  # pylint: disable=unused-argument
    """
    Sign a given `fname` and write the signature to `ofname`.
    """
    if private_key is None:
        private_key = Options.private_key
    # NOTE: This is intended to crash if there's some number of keys other than
    # exactly 1 read from the private_key file:
    the_keys = list(read_certs(private_key))
    if not the_keys:
        log.error(
            "unable to sign %s with %s (no such file or error reading certs)",
            os.path.abspath(fname),
            os.path.abspath(private_key),
        )
        return
    first_key = the_keys[0]
    hasher, chosen_hash = hash_target(fname, obj_mode=True)
    args = {"data": hasher.finalize()}

    salt_padding_bits = _format_padding_bits(Options.salt_padding_bits)

    log.error("signing %s using %s", fname, private_key)

    if isinstance(first_key, rsa.RSAPrivateKey):
        log.error("signing %s using SBP:%s", fname, _format_padding_bits_txt(salt_padding_bits))
        args["padding"] = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=salt_padding_bits)
        args["algorithm"] = utils.Prehashed(chosen_hash)
    sig = first_key.sign(**args)
    with open(ofname, "w") as fh:
        log.error("writing signature of %s to %s", os.path.abspath(fname), os.path.abspath(ofname))
        fh.write(encode_pem(sig, "Detached Signature of {}".format(fname)))
        fh.write("\n")


VERIFY_CACHE = dict()


def _clean_verify_cache(old=None):
    if old is None:
        old = Options.verify_cache_age
    if old < 1:
        return
    old = time() - old
    to_remove = set()
    for k, v in VERIFY_CACHE.items():
        try:
            if v["t"] < old:
                to_remove.add(k)
        except (TypeError, KeyError):
            to_remove.add(k)
    for k in to_remove:
        del VERIFY_CACHE[k]


def _get_verify_cache(key, auto_clean=None):
    _clean_verify_cache(old=auto_clean)
    log.debug("verify_signature()_get_verify_cache(%s) -> %s", key, VERIFY_CACHE.get(key))
    try:
        return VERIFY_CACHE[key]["v"]
    except (KeyError, TypeError):
        pass


def _set_verify_cache(key, val, auto_clean=0):
    _clean_verify_cache(old=auto_clean)
    log.debug("verify_signature()_set_verify_cache(%s) <- %s", key, val)
    VERIFY_CACHE[key] = dict(t=time(), v=val)
    return val


def verify_signature(
    fname, sfname, public_crt=None, ca_crt=None, extra_crt=None, **kwargs
):  # pylint: disable=unused-argument
    """
    Given the fname, sfname public_crt and ca_crt:

    return STATUS.FAIL if the signature doesn't match
    return STATUS.UNKNOWN if the certificate signature can't be verified with the ca cert
    return STATUS.VERIFIED if both the signature and the CA sig match
    """

    if check_verify_timestamp(fname):
        log_error = log.error
        log_info = log.info
    else:
        log_error = log_info = log.debug

    if Options.verify_cache_age > 0:
        cache_key = _cache_key(fname, sfname, public_crt, ca_crt, extra_crt)
        res = _get_verify_cache(cache_key)
        if res is not None:
            log_info("using cached verify_signature(%s, %s) -> %s", fname, sfname, res)
            return res

    if public_crt is None:
        public_crt = Options.public_crt
    if ca_crt is None:
        ca_crt = Options.ca_crt

    if not (fname and sfname):
        status = STATUS.UNKNOWN
        log_info("!(fname=%s and sfname=%s) => status=%s", fname, sfname, status)
        return status

    short_fname = os.path.basename(fname)

    try:
        with open(sfname, "r") as fh:
            sig = decode_pem(fh.read())
    except IOError:
        status = STATUS.UNKNOWN
        verif_key = ":".join([fname, sfname])
        log_error('%s | file "%s" | status: %s ', short_fname, fname, status)
        return status

    x509 = X509AwareCertBucket(public_crt, ca_crt, extra_crt)
    hasher, chosen_hash = hash_target(fname, obj_mode=True)
    digest = hasher.finalize()

    salt_padding_bits_list = Options.salt_padding_bits
    if not isinstance(salt_padding_bits_list, (list, tuple)):
        salt_padding_bits_list = [salt_padding_bits_list]

    sha256sum = "".join(f"{x:02x}" for x in digest)

    for crt, txt, pcrt_status in x509.public_crt:
        args = {"signature": sig, "data": digest}
        pubkey = crt.get_pubkey().to_cryptography_key()
        for salt_padding_bits in salt_padding_bits_list:
            salt_padding_bits = _format_padding_bits(salt_padding_bits)
            if isinstance(pubkey, rsa.RSAPublicKey):
                args["padding"] = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=salt_padding_bits)
                args["algorithm"] = utils.Prehashed(chosen_hash)
            try:
                pubkey.verify(**args)
                log_info(
                    'verify_signature(%s, %s) | sbp: %s | status: %s | sha256sum: "%s" | (1) public cert fingerprint and requester: "%s"',
                    fname,
                    sfname,
                    _format_padding_bits_txt(salt_padding_bits),
                    pcrt_status,
                    sha256sum,
                    txt,
                )
                if Options.verify_cache_age < 1:
                    return pcrt_status
                return _set_verify_cache(cache_key, pcrt_status)
            except TypeError as tee:
                log_info(
                    "verify_signature(%s, %s) | sbp: %s | internal error using %s.verify() (%s): (2) %s",
                    fname,
                    sfname,
                    _format_padding_bits_txt(salt_padding_bits),
                    type(pubkey).__name__,
                    stringify_cert_files(crt),
                    tee,
                )
            except InvalidSignature:
                log_info(
                    'verify_signature(%s, %s) InvalidSignature | sbp: %s | sha256sum: "%s" | public cert fingerprint and requester: "%s"',
                    fname,
                    sfname,
                    _format_padding_bits_txt(salt_padding_bits),
                    sha256sum,
                    txt,
                )
    status = STATUS.FAIL
    log_error(
        'verify_signature(%s, %s) UnverifiedSignature | status: %s | sha256sum: "%s" | (4)',
        fname,
        sfname,
        status,
        sha256sum,
    )
    return _set_verify_cache(cache_key, status)


def iterate_manifest(mfname):
    """
    Generate an interator from the MANFIEST file. Each iter item is a filename
    (not the digest portion of the line).
    """
    with open(mfname, "r") as fh:
        for line in fh.readlines():
            matched = MANIFEST_RE.match(line)
            if matched:
                _, manifested_fname = matched.groups()
                manifested_fname = normalize_path(manifested_fname)
                yield manifested_fname
