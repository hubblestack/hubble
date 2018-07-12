
import signal
import time

import logging
log = logging.getLogger('hangtime')

def _alive(x):
    try:
        return x.id is not None
    except ReferenceError:
        return False

class HangTime(Exception):
    # NOTE: this will break completely in multithreading
    # it should work just fine in multiprocessing

    prev = list()

    def __init__(self, msg="hang timeout detected", timeout=300, id=0, repeats=False, decay=1.0):
        self.timeout = timeout
        self.started = 0
        self.id = id
        self.repeats = repeats
        self.decay = float(decay)
        super(HangTime, self).__init__(repr(self))

    def __repr__(self):
        return "HT({:0.2f}s, id={})".format(self.timeout, self.id)

    def restore(self, ended=False):
        if not ended and signal.getitimer(signal.ITIMER_REAL)[0] > 0:
            log.debug("timer running, blocking timer stack restore")
            return
        while self.prev and self in self.prev:
            self.prev.pop()
        if self.prev:
            p = self.prev[-1]
            dt = time.time() - p.started
            tr = p.timeout - dt
            if tr > 0:
                log.debug("time remaining on previous timer %s tr=%f, restarting itimer", repr(p), tr)
                signal.signal(signal.SIGALRM, p.fire_timer)
                signal.setitimer(signal.ITIMER_REAL, tr)
            else:
                p.restore()
        else:
            log.debug("timer stack empty after %s, resetting signals/itimers", repr(self))
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, signal.SIG_DFL)

    def fire_timer(self, *sig_param):
        log.debug("timer fired on %s", repr(self))
        if self.repeats:
            self.timeout = max(0.1, self.timeout * self.decay)
            log.debug("restarting timer %s", repr(self))
            signal.setitimer(signal.ITIMER_REAL, self.timeout)
        else:
            self.restore()
        raise self

    def __enter__(self):
        log.debug("watching for process hangs %s", repr(self))
        self.prev.append(self)
        signal.signal(signal.SIGALRM, self.fire_timer)
        self.started = time.time()
        signal.setitimer(signal.ITIMER_REAL, self.timeout)
        return self

    def __exit__(self, e_type, e_obj, e_tb):
        if not isinstance(e_obj, HangTime):
            log.debug("%s exited with-block normally", repr(self))
        else:
            log.debug("%s exited with-block via exception", repr(self))
        self.restore(ended=True)
        if not self.prev:
            log.debug("nolonger watching for process hangs %s", repr(self))

def hangtime_wrapper(**ht_kw):
    def _decorator(actual):
        def _frobnicator(*a, **kw):
            with HangTime(**ht_kw):
                return actual(*a, **kw)
        return _frobnicator
    return _decorator
