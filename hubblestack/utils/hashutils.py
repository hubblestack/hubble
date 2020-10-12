# encoding: utf-8
"""
A collection of hashing and encoding utils.
"""
# Import python libs
import hashlib

import hubblestack.utils.files
import hubblestack.utils.stringutils


def get_hash(path, form="sha256", chunk_size=65536):
    """
    Get the hash sum of a file

    This is better than ``get_sum`` for the following reasons:
        - It does not read the entire file into memory.
        - It does not return a string on error. The returned value of
            ``get_sum`` cannot really be trusted since it is vulnerable to
            collisions: ``get_sum(..., 'xyz') == 'Hash xyz not supported'``
    """
    hash_type = hasattr(hashlib, form) and getattr(hashlib, form) or None
    if hash_type is None:
        raise ValueError('Invalid hash type: {0}'.format(form))

    with hubblestack.utils.files.fopen(path, 'rb') as ifile:
        hash_obj = hash_type()
        # read the file in in chunks, not the entire file
        for chunk in iter(lambda: ifile.read(chunk_size), b''):
            hash_obj.update(chunk)
        return hash_obj.hexdigest()


def sha256_digest(instr):
    """
    Generate a sha256 hash of a given string.
    """
    return hubblestack.utils.stringutils.to_unicode(
        hashlib.sha256(hubblestack.utils.stringutils.to_bytes(instr)).hexdigest()
    )
