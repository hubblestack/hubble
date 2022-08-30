import logging
import os
import re
from binascii import b2a_base64, a2b_base64
from collections import OrderedDict
from enum import Enum

import hubblestack.utils
from hubblestack.utils.signing import (
    Options,
    verify_signature,
    iterate_manifest,
    MANIFEST_RE,
    hash_target,
    check_verify_timestamp,
)


def encode_pem(data: bytes, marker: str) -> str:
    """
    Encode a bytestring as base64, using the PEM format.
    Parameters:
        data (bytes) : payload that will be encoded
        marker (str) : PEM format specific header
    Returns:
        PEM-encoded string
    """
    output = "-----BEGIN {}-----\n".format(marker)
    chunks = [b2a_base64(data[i : i + 48]).decode("latin-1") for i in range(0, len(data), 48)]
    output += "".join(chunks)
    output += "-----END {}-----".format(marker)
    return output


def decode_pem(data: str) -> bytes:
    """
    Decode a bytestring encoded in the PEM format
    Parameters
        data (str): payload that will be decoded
    Returns:
         output (bytes)
    """
    # Verify Pre-Encapsulation Boundary
    pattern = re.compile(r"\s*-----BEGIN (.*)-----\s+")
    m = pattern.match(data)
    if not m:
        raise ValueError("Not a valid PEM pre boundary")
    marker = m.group(1)

    # Verify Post-Encapsulation Boundary
    pattern = re.compile(r"-----END (.*)-----\s*$")
    m = pattern.search(data)
    if not m or m.group(1) != marker:
        raise ValueError("Not a valid PEM post boundary")

    data = data.replace(" ", "").split()
    output = a2b_base64("".join(data[1:-1]))

    return output


def find_file_func_wrapper(not_found=None, real_path="path"):
    """
    Wrap a filesystem find_file function and return the original result if the
    MANIFEST and SIGNATURE indicate the file is valid. If the file is not verified
    and Options.require_verify is False (the default); but the file did not
    explicitly fail to match the MANIFEST, continue to return the original find result.

    Otherwise, return a pretend not-found result instead of the original repo result.
    """
    if not not_found:
        not_found = {"path": "", "rel": ""}

    def wrapper(find_file_func):
        def normalize_search_path(fnd):
            """
            Since `real_path` is poorly named, we make it so that is contains the name
            of the key where we'll find the real path of the file we're finding with
            find_file_func()
            """
            return fnd.get(real_path, fnd.get("path", ""))

        def inner(path, saltenv, *a, **kwargs):
            f_path = find_file_func(path, saltenv, *a, **kwargs)
            p_path = normalize_search_path(f_path)

            if not p_path:
                # if the file doesn't exist anyway, there's no reason to continue
                return f_path

            path_manifest = normalize_search_path(find_file_func(Options.manifest_file_name, saltenv, *a, **kwargs))
            path_signature = normalize_search_path(find_file_func(Options.signature_file_name, saltenv, *a, **kwargs))
            path_certificate = normalize_search_path(
                find_file_func(Options.certificates_file_name, saltenv, *a, **kwargs)
            )

            log.debug(
                'path: %s | f_path: %s | p_path: %s | create_manifest: "%s" | signature: "%s"',
                path,
                f_path,
                p_path,
                path_manifest,
                path_signature,
            )

            verify_res = verify_files(
                [p_path],
                mfname=path_manifest,
                sfname=path_signature,
                public_crt=Options.public_crt,
                ca_crt=Options.ca_crt,
                extra_crt=path_certificate,
            )

            log.debug("verify: %s", dict(**verify_res))

            vrg = verify_res.get(p_path, STATUS.UNKNOWN)
            if vrg == STATUS.VERIFIED:
                return f_path
            if vrg == STATUS.UNKNOWN and not Options.require_verify:
                return f_path
            log.debug("claiming not found: %s (%s)", path, f_path)
            if log.isEnabledFor(logging.DEBUG):
                import inspect

                for idx, frame in enumerate(inspect.stack()[1:60]):
                    if "hubblestack" in frame.filename:
                        log.debug("find caller[%d] %s %s() %s", idx, frame.filename, frame.function, frame.lineno)
            return dict(**not_found)

        return inner

    return wrapper


def stringify_ossl_cert(certificate_obj):
    """
    Try to stringify a cert object into its subject components and digest hexification.

    E.g. (with extra newline added for line-wrap):
        3E:9C:58:F5:27:89:A8:F4:B7:AB:4D:1C:56:C8:4E:F0:03:0F:C8:C3
        C=US/ST=State/L=City/O=Org/OU=Group/CN=Certy Cert #1
    """
    if isinstance(certificate_obj, (list, tuple)):
        return ", ".join([stringify_ossl_cert(i) for i in certificate_obj])
    return "/".join(["=".join([j.decode() for j in i]) for i in certificate_obj.get_subject().get_components()])


def normalize_path(path, trunc=None):
    """
    Attempt to translate /<path>/./<to>////<files>/.bashrc
    to /<path>/<to>/<files>/.bashrc; optionally truncating
    the path if it starts with the given trunc kwarg string.
    """
    norm = os.path.normpath(path)
    if trunc:
        if norm.startswith(os.path.sep + trunc + os.path.sep):
            norm = norm[len(trunc) + 2 :]
        elif norm.startswith(trunc + os.path.sep):
            norm = norm[len(trunc) + 1 :]
        elif norm.startswith(os.path.sep + trunc):
            norm = norm[len(trunc) + 1 :]
        elif norm.startswith(trunc):
            norm = norm[len(trunc) :]
    return norm


def run_callback(targets, callback):
    """
    Recursively invoke the `callback` on each target. Targets can be either files or
    directories.
    """
    for filename in targets:
        if os.path.isfile(filename):
            callback(filename)
        if os.path.isdir(filename):
            for dirpath, dirnames, filenames in os.walk(filename):
                for fname in filenames:
                    absolute_file_path = os.path.join(dirpath, fname)
                    callback(absolute_file_path)


def _get_file_stat(fname):
    if isinstance(fname, str):
        try:
            st = os.stat(fname)  # pylint: disable=invalid-name ; this is fine
            return os.path.abspath(fname), st.st_mtime, st.st_ctime
        except FileNotFoundError:
            pass
    return tuple()


def _cache_key(*files):
    return sum((_get_file_stat(x) for x in files), tuple())


class STATUS(Enum):
    """container for status code (strings)"""

    FAIL = "fail"
    VERIFIED = "verified"
    UNKNOWN = "unknown"


class Options(object):
    """
    The Options class is simply a convenience interface for interacting with repo_signing options.

    Instead of `__mods__['config.get']('repo_signing:public_crt')`, write `Options.public_crt`.
    """

    class Defaults:
        """defaults storage for options"""

        require_verify = False
        verify_cache_age = 600
        ca_crt = "/etc/hubble/sign/ca-root.crt"
        public_crt = "/etc/hubble/sign/public.crt"
        private_key = "/etc/hubble/sign/private.key"
        manifest_file_name = "MANIFEST"
        signature_file_name = "SIGNATURE"
        certificates_file_name = "CERTIFICATES"
        salt_padding_bits = ["max", 32]
        # The first generation signature padding bits were 32 (only) the
        # crypto-recommended is "however many we can fit". AWS CloudHSM is
        # incompatible with max, ... we'll need to try both. See below.

    def __getattribute__(self, name):
        """If the option exists in the default pseudo meta class
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
            return __mods__["config.get"]("repo_signing:{}".format(name), default)
        except AttributeError:
            raise


log = logging.getLogger(__name__)


def verify_files(targets, mfname=None, sfname=None, public_crt=None, ca_crt=None, extra_crt=None):
    """given a list of `targets`, a MANIFEST, and a SIGNATURE file:

    1. Check the signature of the create_manifest, mark the 'MANIFEST' item of the return as:
         STATUS.FAIL if the signature doesn't match
         STATUS.UNKNOWN if the certificate signature can't be verified with the ca cert
         STATUS.VERIFIED if both the signature and the CA sig match
    2. mark all targets as STATUS.UNKNOWN
    3. check the digest of each target against the create_manifest, mark each file as
         STATUS.FAIL if the digest doesn't match
         STATUS.*, the status of the MANIFEST file above

    return a mapping from the input target list to the status values (a dict of filename: status)
    """

    if mfname is None:
        mfname = Options.manifest_file_name
    if sfname is None:
        sfname = Options.signature_file_name
    if public_crt is None:
        public_crt = Options.public_crt
    if ca_crt is None:
        ca_crt = Options.ca_crt

    log.debug(
        "verifying: files: %s | mfname: %s | sfname: %s | public_crt: %s| ca_crt: %s",
        targets,
        mfname,
        sfname,
        public_crt,
        ca_crt,
    )

    ret = OrderedDict()
    ret[mfname] = verify_signature(mfname, sfname=sfname, public_crt=public_crt, ca_crt=ca_crt, extra_crt=extra_crt)
    # ret[mfname] is the strongest claim we can make about the files we're
    # verifiying if they match their hash in the create_manifest, the best we can say
    # is whatever is the status of the create_manifest itself.

    mf_dir, _ = os.path.split(mfname)
    sf_dir, _ = os.path.split(sfname)

    if mf_dir and mf_dir == sf_dir:
        if hubblestack.utils.platform.is_windows():
            trunc = mf_dir
        else:
            trunc = mf_dir + "/"
    else:
        trunc = None

    # pre-populate digests with STATUS.UNKNOWN, skip things that shouldn't be
    # digested (MANIFEST, SIGNATURE, etc) and build a database mapping
    # normalized names back to given target names.
    xlate = dict()
    digests = OrderedDict()
    if not targets:
        targets = list(iterate_manifest(mfname))
    for otarget in targets:
        target = normalize_path(otarget, trunc=trunc)

        log.debug("found create_manifest for %s (%s)", otarget, target)
        if otarget != target:
            xlate[target] = otarget
        if target in digests or target in (mfname, sfname):
            continue
        digests[target] = STATUS.UNKNOWN
    # populate digests with the hashes from the MANIFEST
    if os.path.isfile(mfname):
        with open(mfname, "r") as fh:
            for line in fh.readlines():
                matched = MANIFEST_RE.match(line)
                if matched:
                    digest, manifested_fname = matched.groups()
                    manifested_fname = normalize_path(manifested_fname)
                    if manifested_fname in digests:
                        digests[manifested_fname] = digest
    # number of seconds before a FAIL or UNKNOWN is set to the returner
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
        if check_verify_timestamp(digest):
            if status == STATUS.FAIL:
                log_level = log.error
            elif status == STATUS.UNKNOWN:
                log_level = log.error
        # logs according to the STATUS of target file
        log_level(
            'file: "%s" | status: %s | create_manifest sha256: "%s" | real sha256: "%s"',
            vfname,
            status,
            digest,
            new_hash,
        )
        ret[vfname] = status

    # fix any normalized names so the caller gets back their specified targets
    for k, v in xlate.items():
        ret[v] = ret.pop(k)
    return ret
