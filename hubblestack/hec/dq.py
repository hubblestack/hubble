# -*- encoding: utf-8 -*-

import bz2
import os
import logging
import time
import shutil
import json
from collections import deque

__all__ = [
    'QueueTypeError', 'QueueCapacityError', 'MemQueue', 'DiskQueue',
    'DiskBackedQueue', 'DEFAULT_MEMORY_SIZE', 'DEFAULT_DISK_SIZE',
]

log = logging.getLogger(__name__)

OK_TYPES = (str,)
SPLUNK_MAX_MSG = 100000 # 100k
DEFAULT_MEMORY_SIZE = SPLUNK_MAX_MSG * 5 # 500k
DEFAULT_DISK_SIZE = DEFAULT_MEMORY_SIZE * 1000 # 0.5GB

class QueueTypeError(Exception):
    pass

class QueueCapacityError(Exception):
    pass

class OKTypesMixin:
    def __init__(self, ok_types=OK_TYPES):
        self.init_types(ok_types)

    def init_types(self, ok_types):
        self.ok_types = ok_types

    def check_type(self, item):
        if not isinstance(item, self.ok_types):
            raise QueueTypeError('type({0}) is not ({1})'.format(type(item), self.ok_types))

class NoQueue(object):
    cn = 0
    def put(self, *a, **kw):
        log.debug('no-queue.put() dumping event')
        pass
    def getz(self, *a, **kw):
        log.debug('no-queue.put() nothing to dequeue')
        pass
    def __bool__(self):
        return False
    __nonzero__ = __bool__ # stupid python2


class DiskQueue(OKTypesMixin):
    sep = b' '

    def __init__(self, directory, size=DEFAULT_DISK_SIZE, ok_types=OK_TYPES, fresh=False, compression=0):
        self.init_types(ok_types)
        self.init_dq(directory, size)
        self.compression = compression
        log.debug('DiskQueue.__init__(%s, compression=%d)', directory, compression)
        if fresh:
            self.clear()
        self._count()

    def __bool__(self):
        return True
    __nonzero__ = __bool__ # stupid python2

    def compress(self, dat):
        if not self.compression:
            return dat
        def _bz2(x):
            b = bz2.BZ2Compressor(self.compression)
            d = b.compress(x)
            return d + b.flush()
        return _bz2(dat)

    def decompress(self, dat):
        if dat.startswith('BZ'):
            try:
                return bz2.BZ2Decompressor().decompress(dat)
            except IOError:
                pass
        return dat

    def init_dq(self, directory, size):
        self.directory = directory
        self.size = size

    def _mkdir(self, partial=None):
        d = self.directory
        if partial is not None:
            d = os.path.join(d, partial)
        if not os.path.isdir(d):
            os.makedirs(d)
        return d

    def clear(self):
        """ clear the queue """
        if os.path.isdir(self.directory):
            shutil.rmtree(self.directory)

    def _fanout(self, name):
        return (name[0:4], name[4:])

    def accept(self, item):
        """ test to see whether the given item would fit in the queue under the queue's size restraints """
        if len(item) + self.sz > self.size:
            return False
        return True

    def put(self, item, **meta):
        """ Put an item in the queue at the end (FIFO order)
            put() also takes an arbitrary number of meta data items (kwargs); which,
            if given, it will write to a meta data file describing the entry.
        """
        self.check_type(item)
        if not self.accept(item):
            raise QueueCapacityError('refusing to accept item due to size')
        fanout, remainder = self._fanout('{0}.{1}'.format(int(time.time()), self.cn))
        d = self._mkdir(fanout)
        f = os.path.join(d, remainder)
        with open(f, 'wb') as fh:
            log.debug('writing item to disk cache')
            fh.write(self.compress(item))
        if meta:
            with open(f + '.meta', 'w') as fh:
                json.dump(meta, fh)
        self._count()

    def peek(self):
        """ look at the next item in the queue, but don't actually remove it from the queue """
        for fname in self.files:
            with open(fname, 'rb') as fh:
                return self.decompress(fh.read())

    def get(self):
        """ get the next item from the queue """
        for fname in self.files:
            with open(fname, 'rb') as fh:
                ret = self.decompress(fh.read())
            os.unlink(fname)
            self._count()
            return ret

    def getz(self, sz=SPLUNK_MAX_MSG):
        """ fetch items from the queue and concatenate them together using the
            spacer ' ' until the size reaches (but does not exceed) the size
            kwargs (sz).

            kwargs:
                sz : the maxsize of the queue fetch (default: SPLUNK_MAX_MSG=100k)
        """
        # Is it "dangerous" to unlink files during the os.walk (via generator)?
        # .oO( probably doesn't matter )
        r = b''
        for fname in self.files:
            with open(fname, 'rb') as fh:
                p = self.decompress(fh.read())
            if r:
                if len(r) + len(self.sep) + len(p) > sz:
                    break
                r += self.sep
            r += p
            os.unlink(fname)
        self._count()
        return r

    def pop(self):
        """ remove the next item from the queue (do not return it); useful with .peek() """
        for fname in self.files:
            os.unlink(fname)
            break
        self._count()

    @property
    def files(self):
        """ generate all filenames in the diskqueue (returns iterable) """
        def _k(x):
            try:
                return [ int(i) for i in x.split('.') ]
            except:
                pass
            return x
        for path, dirs, files in sorted(os.walk(self.directory)):
            for fname in [ os.path.join(path, f) for f in sorted(files, key=_k) ]:
                yield fname

    def _count(self):
        self.cn = 0
        self.sz = 0
        for fname in self.files:
            self.sz += os.stat(fname).st_size
            self.cn += 1
        log.debug('disk cache sizes: cn=%d sz=%d', self.cn, self.sz)

    @property
    def msz(self):
        """ The size of the queue as it would be returned from getz() iff getz had no size limit """
        return self.sz + max(0, len(self.sep) * (self.cn -1))

    def __len__(self):
        return self.msz
