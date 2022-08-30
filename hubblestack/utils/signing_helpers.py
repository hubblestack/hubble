import logging
import os
import re
from binascii import b2a_base64, a2b_base64
from enum import Enum

from hubblestack.utils.signing import Options, log, verify_files


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
