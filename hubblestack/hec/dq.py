# -*- encoding: utf-8 -*-

import bz2
import os
import logging
import time
import shutil
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

class MemQueue(OKTypesMixin):
    sep = b' '

    def __init__(self, size=DEFAULT_MEMORY_SIZE, ok_types=OK_TYPES):
        self.init_types(ok_types)
        self.init_mq(size)

    def __bool__(self):
        return True
    __nonzero__ = __bool__ # stupid python2

    def init_mq(self, size):
        self.size = size
        # compose rather than inherit to limit operations to append()/popleft() and
        # ignore the rest of the deque() functionality
        self.mq = deque()

    def accept(self, item):
        """ test to see whether the given item would fit in the queue under the queue's size restraints """
        if len(item) + self.sz > self.size:
            return False
        return True

    def put(self, item):
        """ Put an item in the queue at the end (FIFO order) """
        self.check_type(item)
        if not self.accept(item):
            raise QueueCapacityError('refusing to accept item due to size')
        self.mq.append(item)

    def unget(self, item):
        """ Put an item (back) in the queue at the front (LIFO order)

            This is meant to reverse a previous .get() that later turns out to
            be un-needed.
        """
        self.check_type(item)
        self.mq.appendleft(item)

    def get(self):
        """ get the next item from the queue """
        if len(self.mq) > 0:
            return self.mq.popleft()

    def pop(self):
        """ pop an item from the queue """
        self.mq.popleft()

    def getz(self, sz=SPLUNK_MAX_MSG):
        """ get items from the queue and concatenate them together using the
        spacer ' ' until the size reaches (but does not exceed) the kwarg sz.

            kwargs:
                sz : the maxsize of the queue fetch (default: SPLUNK_MAX_MSG=100k)
        """
        r = b''
        while len(self.mq) > 0 and len(r) + len(self.sep) + len(self.peek()) < sz:
            if r:
                r += self.sep
            r += self.mq.popleft()
        return r

    def peek(self):
        """ look at the next item in the queue, but don't actually remove it from the queue """
        if len(self.mq) > 0:
            return self.mq[0]

    @property
    def sz(self):
        """ the size of the queue in bytes (not counting any needed spacers) """
        s = 0
        for i in self.mq:
            s += len(i)
        return s

    @property
    def cn(self):
        """ the size of the queue in items (the count) """
        return len(self.mq)

    @property
    def msz(self):
        """ The size of the queue as it would be returned from getz() iff getz had no size limit """
        return self.sz + max(0, len(self.sep) * (self.cn -1))

    def __len__(self):
        return self.msz


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

    def put(self, item):
        """ Put an item in the queue at the end (FIFO order) """
        self.check_type(item)
        if not self.accept(item):
            raise QueueCapacityError('refusing to accept item due to size')
        fanout, remainder = self._fanout('{0}.{1}'.format(int(time.time()), self.cn))
        d = self._mkdir(fanout)
        f = os.path.join(d, remainder)
        with open(f, 'wb') as fh:
            log.debug('writing item to disk cache')
            fh.write(self.compress(item))
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

class DiskBackedQueue:
    def __init__(self, directory, mem_size=DEFAULT_MEMORY_SIZE,
            disk_size=DEFAULT_DISK_SIZE, ok_types=OK_TYPES, fresh=False):

        self.dq = DiskQueue(directory, size=disk_size, ok_types=ok_types, fresh=fresh)
        self.mq = MemQueue(size=mem_size, ok_types=ok_types)

    def __bool__(self):
        return True
    __nonzero__ = __bool__ # stupid python2

    def put(self, item):
        """ Put an item in the queue at the end (FIFO order) """
        try:
            self.mq.put(item)
        except QueueCapacityError:
            self.dq.put(item)

    def peek(self):
        """ look at the next item in the queue, but don't actually remove it from the queue """
        r = self.mq.peek()
        if r is None:
            r = self.dq.peek()
        return r

    def pop(self):
        if self.mq.cn:
            self.mq.pop()
        elif self.dq.cn:
            self.dq.pop()

    def unget(self, msg):
        """ Put an item (back) in the queue at the front (LIFO order)

            This is meant to reverse a previous .get() that later turns out to
            be un-needed.
        """
        self.mq.unget(msg)

    def _disk_to_mem(self):
        while self.dq.cn > 0:
            # NOTE: dq.peek() read()s the file but doesn't unlink()
            # dq.get() read()s the file and unlink()s it
            # dq.pop() just unlink()s the file
            # we attempt here to read each file exactly once — until the
            # stopping condition
            p = self.dq.peek()
            if self.mq.accept(p):
                self.mq.put(p)
                self.dq.pop()
            else:
                break

    def get(self):
        """ get the next item from the queue """
        r = self.mq.get()
        if r is None:
            r = self.dq.get()
        self._disk_to_mem()
        return r

    def getz(self, sz=SPLUNK_MAX_MSG):
        """ fetch items from the queue and concatenate them together using the
            spacer ' ' until the size reaches (but does not exceed) the size
            kwargs (sz).

            kwargs:
                sz : the maxsize of the queue fetch (default: SPLUNK_MAX_MSG=100k)
        """
        r = self.mq.getz(sz)
        if r is None:
            r = self.dq.getz(sz)
        elif len(r) < sz-1:
            r2 = self.dq.getz(sz-(len(r)+1))
            if r2:
                r += b' ' + r2
        self._disk_to_mem()
        return r

    @property
    def cn(self):
        """ the size of the queue in items (the count) """
        return self.mq.cn + self.dq.cn

    @property
    def msz(self):
        """ The size of the queue as it would be returned from getz() iff getz had no size limit """
        mq_msz = self.mq.msz
        dq_msz = self.dq.msz
        if mq_msz and dq_msz:
            return 1 + mq_msz + dq_msz
        if mq_msz:
            return mq_msz
        if dq_msz:
            return dq_msz
        return 0

    @property
    def sz(self):
        """ the size of the queue in bytes (not counting any needed spacers) """
        return self.mq.sz + self.dq.sz
