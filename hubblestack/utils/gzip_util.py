# -*- coding: utf-8 -*-
"""
    salt.utils.gzip
    ~~~~~~~~~~~~~~~
    Helper module for handling gzip consistently between 2.7+ and 2.6-
"""

from __future__ import absolute_import, unicode_literals, print_function

# Import python libs
import gzip
import io

StringIO = io.StringIO
BytesIO = io.BytesIO


class GzipFile(gzip.GzipFile):
    def __init__(self, filename=None, mode=None,
                 compresslevel=9, fileobj=None):
        gzip.GzipFile.__init__(self, filename, mode, compresslevel, fileobj)

    ### Context manager (stolen from Python 2.7)###
    def __enter__(self):
        """Context management protocol.  Returns self."""
        return self

    def __exit__(self, *args):
        """Context management protocol.  Calls close()"""
        self.close()


def compress(data, compresslevel=9):
    """
    Returns the data compressed at gzip level compression.
    """
    buf = BytesIO()
    with open_fileobj(buf, 'wb', compresslevel) as ogz:
        if not isinstance(data, bytes):
            data = data.encode(__salt_system_encoding__)
        ogz.write(data)
    compressed = buf.getvalue()
    return compressed


def uncompress(data):
    buf = BytesIO(data)
    with open_fileobj(buf, 'rb') as igz:
        unc = igz.read()
        return unc


def open_fileobj(fileobj, mode='rb', compresslevel=9):
    if hasattr(gzip.GzipFile, '__enter__'):
        return gzip.GzipFile(
            filename='', mode=mode, fileobj=fileobj,
            compresslevel=compresslevel
        )
    return GzipFile(
        filename='', mode=mode, fileobj=fileobj, compresslevel=compresslevel
    )
