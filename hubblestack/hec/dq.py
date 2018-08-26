
from diskcache import Deque
from sqlite3 import DatabaseError as SQLiteDBError
import shutil, os

class DiskQueue(object):
    def __init__(self, directory='/var/cache/hubble/dq', max_items=None, max_size=None):
        self.directory = directory
        self.max_items = max_items
        self.max_size  = max_size

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
        except SQLiteDBError:
            # XXX: is this dangerous?
            # The notion is: if we can't open the database because it's
            # corrupted or the wrong sqlite version or whatever; just give up
            # and consider those msgs lost.
            if os.path.isdir(directory) and os.path.isfile(os.path.join(directory, 'cache.db')):
                shutil.rmtree(directory)
            # If it still doesn't work, crash in the previous way
            return Deque(directory=self.directory)

    @property
    def stats(self):
        return {'items': self.count, 'size': self.size}

    @property
    def count(self):
        return len(self.q)

    @property
    def size(self):
        ''' Try to guess the size of the cache.  It will never bee 100%
        accurate because the cache is backed by SQLite3, which has a wal
        journal.  The size of the journal is unpredictable at best.
        '''
        s = 0
        for dp, dn, fn in os.walk(self.directory):
            for pn in [ os.path.join(dp, f) for f in fn ]:
                s += os.stat(pn).st_size
        return s

    def _drop_for_size(self, q):
        if self.max_items and self.max_items > 0:
            while q.count > self.max_items:
                q.pop()
        if self.max_size and self.max_size >= 1000:
            while self.size > self.max_size:
                self.q.pop()

    def push(self, item):
        q = self.q
        q.append(item)
        self._drop_for_size(q)

    def peek(self, idx=0):
        try:
            self.l = self.q[idx]
        except IndexError:
            self.l = None
        return self.l

    def pull(self):
        try:
            self.l = self.q.popleft()
        except IndexError:
            self.l = None
        return self.l

    # copy *some* of the operator overloading up from the q
    def __iter__(self):
        return self.q.__iter__

    def __getitem__(self, idx):
        return self.q.__getitem__(idx)

    def __contains__(self, thing):
        return self.q.__contains__(thing)

    def clear(self):
        self.q.clear()

