
from collections import namedtuple
import signal
import time

import logging
log = logging.getLogger('hangtime')

class HangTime(Exception):
    # NOTE: this will break completely in multithreading
    # it should work just fine in multiprocessing

    pitem = namedtuple('pitem', ['started','timeout','handler'])
    prev = list()

    def __init__(self, msg="hang timeout detected", timeout=300, id=0):
        super(HangTime, self).__init__(msg)
        self.timeout = timeout
        self.started = 0
        self.id = id

    def restore(self):
        p = self.prev.pop()
        signal.signal(signal.SIGALRM, p.handler)

    def fire_timer(self, *sig_param):
        raise self

    def __enter__(self):
        log.info("watching for process hangs (%s, %s)", self.timeout, self.id)
        self.prev.append( self.pitem(self.started, self.timeout, signal.getsignal(signal.SIGALRM)) )
        signal.signal(signal.SIGALRM, self.fire_timer)
        self.started = time.time()
        signal.setitimer(signal.ITIMER_REAL, self.timeout)
        return self

    def __exit__(self, e_type, e_obj, e_tb):
        log.info("nolonger watching for process hangs (%s, %s)", self.timeout, self.id)
        self.restore()
        if self.prev:
            p = self.prev[-1]
            dt = time.time() - p.started
            tr = p.timeout - dt
            if tr > 0:
                signal.setitimer(signal.ITIMER_REAL, dt)
                return True # meaning we handled this exception internally

def hangtime_wrapper(timeout=1000):
    def _decorator(actual):
        def _frobnicator(*a, **kw):
            with HangTime(timeout=timeout):
                return actual(*a, **kw)
        return _frobnicator
    return _decorator
