# -*- encoding: utf-8 -*-

import bz2
import os
import logging
import time
import shutil
import json
from collections import deque
from hubblestack.utils.misc import numbered_file_split_key
from hubblestack.utils.encoding import encode_something_to_bytes, decode_something_to_string

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
    cn = sz = 0

    def __init__(self, directory, size=DEFAULT_DISK_SIZE, ok_types=OK_TYPES, fresh=False, compression=0):
        self.init_types(ok_types)
        self.init_dq(directory, size)
        self.compression = compression
        log.debug('DiskQueue.__init__(%s, compression=%d)', directory, compression)
        if fresh:
            self.clear()
        self._count()
        self.double_check_cnsz = bool(os.environ.get('DOUBLE_CHECK_CNSZ'))

    def __bool__(self):
        return True
    __nonzero__ = __bool__ # stupid python2

    def compress(self, dat):
        dat = encode_something_to_bytes(dat)
        if not self.compression:
            return dat
        def _bz2(x):
            b = bz2.BZ2Compressor(self.compression)
            d = b.compress(x)
            return d + b.flush()
        return _bz2(dat)

    def unlink_(self, fname):
        names = (fname, fname + '.meta')
        for name in names:
            if os.path.isfile(name):
                os.unlink(name)

    def decompress(self, dat):
        dat = encode_something_to_bytes(dat)
        if dat.startswith(b'BZ'):
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
        bstr = self.compress(item)
        if not self.accept(bstr):
            raise QueueCapacityError('refusing to accept item due to size')
        fanout, remainder = self._fanout('{0}.{1}'.format(int(time.time()), self.cn))
        d = self._mkdir(fanout)
        f = os.path.join(d, remainder)
        with open(f, 'wb') as fh:
            log.debug('writing item to disk cache')
            fh.write(bstr)
        if meta:
            with open(f + '.meta', 'w') as fh:
                json.dump(meta, fh)
        self.cn += 1
        self.sz += len(bstr)
        if self.double_check_cnsz:
            self._count(double_check_only=True, tag='put')

    def read_meta(self, fname):
        try:
            with open(fname + '.meta', 'r') as fh:
                return json.load(fh)
        except ValueError:
            # can't quite read the json
            pass
        except IOError:
            # no such file
            pass
        return dict()

    def peek(self):
        """ look at the next item in the queue, but don't actually remove it from the queue
            returns: data_octets, meta_data_dict
        """
        for fname in self.files:
            with open(fname, 'rb') as fh:
                return decode_something_to_string(self.decompress(fh.read())), self.read_meta(fname)

    def iter_peek(self):
        ''' iterate and return all items in the disk queue (without removing any) '''
        for fname in self.files:
            with open(fname, 'rb') as fh:
                yield self.decompress(fh.read()), self.read_meta(fname)

    def iter_peek(self):
        ''' iterate and return all items in the disk queue (without removing any) '''
        for fname in self.files:
            with open(fname, 'rb') as fh:
                yield self.decompress(fh.read()), self.read_meta(fname)

    def get(self):
        """ get the next item from the queue
            returns: data_octets, meta_data_dict
        """
        for fname in self.files:
            with open(fname, 'rb') as fh:
                dat = self.decompress(fh.read())
            mdat = self.read_meta(fname)
            sz = os.stat(fname).st_size
            self.unlink_(fname)
            self.cn -= 1
            self.sz -= sz
            if self.double_check_cnsz:
                self._count(double_check_only=True, tag='get')
            return decode_something_to_string(dat), mdat

    def getz(self, sz=SPLUNK_MAX_MSG):
        """ fetch items from the queue and concatenate them together using the
            spacer ' ' until the size reaches (but does not exceed) the size
            kwargs (sz).

            kwargs:
                sz : the maxsize of the queue fetch (default: SPLUNK_MAX_MSG=100k)

            returns: data_octets, meta_data_dict
        """
        # Is it "dangerous" to unlink files during the os.walk (via generator)?
        # .oO( probably doesn't matter )
        ret = b''
        meta_data = dict()
        for fname in self.files:
            with open(fname, 'rb') as fh:
                partial_data = self.decompress(fh.read())
            if ret:
                if len(ret) + len(self.sep) + len(partial_data) > sz:
                    break
                ret += self.sep
            ret += partial_data
            _md = self.read_meta(fname)
            for k in _md:
                if k not in meta_data:
                    meta_data[k] = list()
                meta_data[k].append( _md[k] )
            self.unlink_(fname)
        self._count()
        for k in meta_data:
            # probably tracking the meta_data for each payload is more work
            # than it's worth; so we just max the meta_data items and assume
            # this only comes up once in a while
            #
            # The usual case is probably:
            # 1. queue 20 or 30 things to disk
            # 2. combine them up on the next loop
            # 3. returning the max of [1,1,1,1,1,1] is 1
            #
            # occasionally this will return something pessimistic
            meta_data[k] = max(meta_data[k])
        return decode_something_to_string(ret), meta_data

    def pop(self):
        """ remove the next item from the queue (do not return it); useful with .peek() """
        for fname in self.files:
            sz = os.stat(fname).st_size
            self.unlink_(fname)
            self.cn -= 1
            self.sz -= sz
            if self.double_check_cnsz:
                self._count(double_check_only=True, tag='pop')
            break

    @property
    def files(self):
        """ generate all filenames in the diskqueue (returns iterable) """
        for path, dirs, files in sorted(os.walk(self.directory)):
            for fname in [os.path.join(path, f) for f in sorted(files, key=numbered_file_split_key)]:
                if fname.endswith('.meta'):
                    continue
                yield fname

    def _count(self, double_check_only=False, tag='unknown'):
        cn = 0
        sz = 0
        for fname in self.files:
            sz += os.stat(fname).st_size
            cn += 1
        if double_check_only:
            log.debug('disk cache sizes: [double check %s] presumed<cn=%d sz=%d> vs actual<cn=%d sz=%d>',
                tag, self.cn, self.sz, cn, sz)
        else:
            self.sz = sz
            self.cn = cn
            log.debug('disk cache sizes: cn=%d sz=%d', self.cn, self.sz)

    @property
    def msz(self):
        """ The size of the queue as it would be returned from getz() iff getz had no size limit """
        return self.sz + max(0, len(self.sep) * (self.cn -1))

    def __len__(self):
        return self.msz
