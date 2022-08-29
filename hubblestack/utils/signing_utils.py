import logging
import re
from binascii import b2a_base64, a2b_base64

from hubblestack.utils.signing import Options, log, verify_files, STATUS


def encode_pem(data: bytes, marker: str) -> str:
    """
    Encode a bytestring as base64, using the PEM format.
    :param data: bytestring to be encoded
    :param marker: PEM format specific header
    :returns: PEM encoded string
    """
    output = "-----BEGIN {}-----\n".format(marker)
    chunks = [b2a_base64(data[i : i + 48]).decode("latin-1") for i in range(0, len(data), 48)]
    output += "".join(chunks)
    output += "-----END {}-----".format(marker)
    return output


def decode_pem(data: bytes) -> str:
    """
    Decode a bytestring encoded in the PEM format
    :param data: bytestring to be decoded
    :returns: decoded string
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
    explicity fail to match the MANIFEST, continue to return the original find result.

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
                'path: %s | f_path: %s | p_path: %s | manifest: "%s" | signature: "%s"',
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
