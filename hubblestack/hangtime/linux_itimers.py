# -*- coding: utf-8 -*-
"""
Module for handling timeouts in code that may not be designed for it.
"""

import signal
import time

import logging
log = logging.getLogger('hangtime')

class HangTime(Exception):
    # NOTE: this will break completely in multithreading
    # it should work just fine in multiprocessing

    prev = list()

    def __init__(self, msg="hang timeout detected", timeout=300, tag=None, repeats=False, decay=1.0):
        """ HangTime wraps code via with block.

        ... code-block:: python
            try:
                with HangTime(timeout=1, tag=1):
                    do_things_that_may_timeout()
                except HangTime as ht:
                    if ht.tag == 1:
                        log.error("something bad happened (code-1):", ht) # w/o traceback
                        log.error(ht) # with traceback

        :param int timeout: timeout in seconds, default 300s

        :param any tag: a tag for differentiating (eg nested) timeouts, default None

        :param bool repeats: by default, HangTime simply raises itself as an
          exception when a timeout is reached and then clears the related timer
          -- in a nested situation, it would then set up the time remaining on
          the next timer.

          In repeats mode, HangTime will instead raise the exception and then
          reset the timer to the starting value (rather than clearing the
          timers). This is useful in situations where the wrapped code catches
          exceptions internally.

        ... code-block:: python

            # salt.loader.grains() catches our HangTime exception as an
            # ordinary SIGALRM event and complains about the error
            # as if it was inside whichever grain ended up taking too long.

            with HangTime(timeout=30, repeats=True):
                __grains__ = salt.loader.grains(__opts__)

            # the timer resets and repeats after any grain takes too long so
            # the next one that takes to long has the benefit of an itimer
            # alarm timeout too.

        :param float decay: if the timer repeats, the decay (default: 1.0)
          is multiplied against the remaining timeout each time the timer
          fires. In this way, the timeout can be made shorter and shorter on
          each timeout (though, the timer will never go below 100ms).

        ... code-block:: text

                        decay=1.0  decay=0.75  decay=0.1
            1st timeout       50s         50s        50s
            2nd timeout       50s       37.5s         5s
            3nd timeout       50s     28.125s       0.5s
            4th timeout       50s     21.094s       0.1s
            4th timeout       50s     15.820s       0.1s
        """
        self.timeout = timeout
        self.started = 0
        self.tag = tag
        self.repeats = repeats
        self.decay = float(decay)
        super(HangTime, self).__init__(repr(self))

    def __repr__(self):
        return "HT({:0.2f}s, tag={})".format(self.timeout, self.tag)

    def restore(self, ended=False):
        """ this method restores the original alarm signal handler, or sets up
            the next timer on the pushdown stack. It takes a single argument
            indicating whether the with block is exiting (so it can know when
            to short-circuit the pushdown stack).
        """
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
        """ when an itimer fires, execution enters this method
            which either clears timers, sets up the next timer in a nest, or
            repeats the last timer as specified by the options.

            After the timers are handled, this method raises the HangTime
            exception.
        """
        log.debug("timer fired on %s", repr(self))
        if self.repeats:
            self.timeout = max(0.1, self.timeout * self.decay)
            log.debug("restarting timer %s", repr(self))
            signal.setitimer(signal.ITIMER_REAL, self.timeout)
        else:
            self.restore()
        raise self

    def __enter__(self):
        """ the logic that starts the timers is normally fired by the with
            keyword though, with just calls this __enter__ function. The timers
            are started here.
        """
        log.debug("watching for process hangs %s", repr(self))
        self.prev.append(self)
        signal.signal(signal.SIGALRM, self.fire_timer)
        self.started = time.time()
        signal.setitimer(signal.ITIMER_REAL, self.timeout)
        return self

    def __exit__(self, e_type, e_obj, e_tb):
        """ when the code leaves the a HangTime with block, execution enters this __exit__
            method. It attempts to clean up any remaining timers.
        """
        if not isinstance(e_obj, HangTime):
            log.debug("%s exited with-block normally", repr(self))
        else:
            log.debug("%s exited with-block via exception", repr(self))
        self.restore(ended=True)
        if not self.prev:
            log.debug("nolonger watching for process hangs %s", repr(self))


def hangtime_wrapper(**ht_kw):
    """ wrap decroated function in a with HangTime block and guard against exceptions
        The options are roughly the same as for HangTime with a minor exception.
        options:
    """
    callback = ht_kw.pop('callback', None)
    def _decorator(actual):
        def _frobnicator(*a, **kw):
            try:
                with HangTime(**ht_kw):
                    return actual(*a, **kw)
            except HangTime as ht:
                res = False
                if callback:
                    try: res = callback(ht)
                    except: pass
                if not res:
                    log.error(ht, exc_info=True)
        return _frobnicator
    return _decorator
