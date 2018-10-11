# -*- encoding: utf-8 -*-

import time
from diskcache import Deque
from sqlite3 import DatabaseError as SQLiteDBError
import shutil, os
import glob

import logging
log = logging.getLogger(__name__)

class DataFormatError(ValueError):
    pass

class DiskQueue(object):
    last_put = last_get = 0

    def __init__(self, directory, max_items=None, max_size=None, restrict_to=None):
        self.directory = directory
        self.max_items = max_items
        self.max_size  = max_size
        self.restrict_to = restrict_to

    @property
    def q(self):
        ''' Open the cache and return the Deque object.  It's desirable for
        this instance to go out of scope frequently to keep the journal size
        nominal.

        If the SQLite3 file that backs the deck gets corrupted or if there's
        SQLite3 version mismatches (etc) this property should nuke the deck and
        quietly start from scratch.
        '''

        try:
            return Deque(directory=self.directory)
        except SQLiteDBError as e:
            # The notion is: if we can't open the database because it's
            # corrupted or the wrong sqlite version or whatever; just give up
            # and consider those msgs lost.
            log.error("problem opening the diskqueue at %s: %s", self.directory, e)
            log.error("deleting the diskqueue")
            cache_file = os.path.join(self.directory, 'cache.db')
            if os.path.isfile(cache_file):
                for f in glob.glob(cache_file + '*'):
                    os.unlink(f)
            # If it still doesn't work, crash in the previous way
            return Deque(directory=self.directory)

    @property
    def stats(self):
        return {'items': self.eventcount, 'size': self.disksize}

    @property
    def eventcount(self):
        return len(self.q)

    @property
    def disksize(self):
        ''' Try to guess the size of the cache.  It will never be 100%
        accurate because the cache is backed by SQLite3, which has a wal
        journal.  The size of the journal is unpredictable at best.
        '''
        if not os.path.isdir(self.directory):
            return 0
        s = 0
        for dp, dn, fn in os.walk(self.directory):
            for pn in [ os.path.join(dp, f) for f in fn ]:
                s += os.stat(pn).st_size
        log.debug('q.size = %d', s)
        return s

    def _drop_for_items(self):
        if self.max_items and self.max_items > 0:
            log.debug('_drop_for_size .max_items %d', self.max_items)
            while self.eventcount > self.max_items:
                self.pop()

    def _drop_for_size(self):
        if self.max_size and self.max_size >= 1000:
            log.debug('_drop_for_size .max_size %d', self.max_size)
            while self.disksize > self.max_size and self.eventcount > 0:
                self.pop()

    def push(self, item):
        log.debug('pushing item to diskqueue')
        if self.restrict_to and not isinstance(item, self.restrict_to):
            raise DataFormatError("items in this queue must be of type {0}".format(self.restrict_to))
        q = self.q
        q.append(item)
        self._drop_for_items()
        self._drop_for_size()
        self.last_put = time.time()
    put = push

    def peek(self, idx=0):
        try:
            return self.q[idx]
        except IndexError:
            pass

    def pull(self):
        if self.eventcount < 1:
            log.debug('pull: empty')
            return
        try:
            r = self.q.popleft()
            self.last_get = time.time()
            log.debug('pull: popped item: %s', r)
            return r
        except IndexError:
            log.debug('pull: failed to pop item')
    pop = pull

    # copy *some* of the operator overloading up from the q
    def __iter__(self):
        return self.q.__iter__()

    def __getitem__(self, idx):
        return self.q[idx]

    def __contains__(self, thing):
        return thing in self.q

    def clear(self):
        self.q.clear()
