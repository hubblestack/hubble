# -*- coding: utf-8 -*-
'''
sudo pkill -10 hubble
echo -n hubble alive:
sudo cat /var/cache/hubble/status.json | jq -r .HEALTH.alive
'''

from collections import namedtuple
from functools import wraps
import time
import json
import signal
import logging

log = logging.getLogger(__name__)

DUMPSTER = '/var/cache/hubble/status.json'

class HubbleStatusResourceNotFound(Exception):
    pass

class HubbleStatus(object):
    '''
        The values tracked by this package (and output by this method) are
        as follows:

        * count: the number of times mark(name) was called
        * dt: the time since the last call of mark(name)
        * dur: the time between mark(name) and fin(name)
        * ema_dt: an exponential moving average of dt
        * ema_dur: an exponential moving average of dur

        The invocations are made most clear with a few examples.

        .. code-block:: python
            from hubblestack.status import HubbleStatus
            # f1 through f4 will be namespaced in the status output
            # as (eg) hubblestack.exciting_package.f1 via the __name__ argument
            hubble_status = HubbleStatus(__name__, 'f1', 'f2', 'f3', 'f4')

            # If the name of the function (`f1` here) matches a named counter
            # this will work just fine as the decorator that tracks duration of
            # calls. Under the hood, it surrounds calls to f1() with mark('f1')
            # and fin('f1") to track calls, time between calls, and call
            # duration.
            @hubble_status.watch
            def f1(blah, blah_key='whatever'):
                do_things()

            # when the name doesn't match, we have to specify it
            @hubble_status.watch('f2')
            def some_f2_thing(blah, blah_key='whatever'):
                etc()

            def whatever():
                # or we can simply mark the counter manually inside some process
                # which will increment the counter and track time between marks
                # but will not attempt to track duration
                while something():
                    hubble_status.mark('f3')
                    do_things()

            def look_at_me(format='\\o/ !!'):
                # to track duration, we have to mark the end of the thing we're
                # tracking (`f4` here)
                hubble_status.mark('f4')
                do_things_that_last_a_while()
                hubble_status.fin('f4') # mark the duration in the counter stack
                return
    '''

    _signaled = False
    dat = dict()
    class Stat(object):
        def __init__(self):
            self.last_t = self.start = time.time()
            self.count  = 0
            self.ema_dt = None
            self.dur = None
            self.ema_dur = None

        @property
        def dt(self):
            return time.time() - self.last_t

        @property
        def asdict(self):
            r = { 'count': self.count, 'last_t': self.last_t,
                'dt': self.dt, 'ema_dt': self.ema_dt }
            if self.dur is not None:
                r.update({'dur': self.dur, 'ema_dur': self.ema_dur})
            return r

        def mark(self):
            ''' mark a counter (ie, increment the count, mark the last_t =
                time.time(), and update the ema_dt)
            '''
            t = time.time()
            self.count += 1
            dt = self.dt
            self.last_t = t
            self.ema_dt  = dt if self.ema_dt is None else 0.5*self.ema_dt + 0.5*dt

        def fin(self):
            ''' mark a counter duration (ie, mark the time since the last mark, and update the ema_dur)
            '''
            self.dur = self.dt
            self.ema_dur  = self.dur if self.ema_dur is None else 0.5*self.ema_dur + 0.5*self.dur


    def __init__(self, namespace, *resources):
        if namespace is None:
            namespace = '_'
        self.namespace = namespace
        if len(resources) == 1 and isinstance(resources[0], (list,tuple,dict)):
            resources = tuple(resources)
        self.resources = [ self._namespaced(x) for x in resources ]
        for r in self.resources:
            self.dat[r] = self.Stat()

    def _namespaced(self, n):
        if self.namespace is None or self.namespace.startswith('_'):
            return n
        if n.startswith(self.namespace + '.'):
            return n
        return self.namespace + '.' + n

    def _checkmark(self, n):
        m = self._namespaced(n)
        if m not in self.resources:
            raise HubbleStatusResourceNotFound('"{}" is not a resource of this HubbleStatus instance')
        return m

    def mark(self, n):
        n = self._checkmark(n)
        self.dat[n].mark()

    def fin(self, n):
        n = self._checkmark(n)
        self.dat[n].fin()

    def watch(self, mark_name):
        ''' wrap a decorated function with a mark/fin pattern
            .. code-block:: python
                hs1 = HubbleStatus(__name__, 'thing1')
                @hs1.watch
                def thing1():
                    time.sleep(2)

                # or

                @hs1.watch('thing1')
                def some_other_name():
                    time.sleep(2)

            This is roughly equivalent to:
            .. code-block:: python
                def whatever():
                    hs1.mark('thing1')
                    time.sleep(2)
                    hs1.fin('thing1')
        '''
        invoke = False
        if callable(mark_name) and hasattr(mark_name, '__name__'):
            # if mark_name is actually a function, invoke the decorator
            # and return the decorated function (see below)
            invoke = mark_name
            mark_name = mark_name.__name__
        def decorator(f):
            @wraps(f)
            def inner(*a, **kw):
                self.mark(mark_name)
                r = f(*a,**kw)
                self.fin(mark_name)
                return r
            return inner
        if invoke:
            return decorator(invoke)
        return decorator

    @classmethod
    def stats(cls):
        ''' Produce a data structure suitable for output as json/yaml —
            intended to be invoked during SIGUSR1.

            The output includes a section (dict key/value) for each tracked
            counter, plus a section regards to the HEALTH of the system, and
            finally a __doc__ section that describes the values inline with the
            data.

            The output (after formatting as json) looks like the following
            (which was truncated and reordered slightly for presentation here).

            .. code-block:: javascript
                {
                  …
                  "hubblestack.daemon.schedule": {
                    "count": 186, "last_t": 1541773420.481246,
                    "dt": 0.2783069610595703, "ema_dt": 0.5015859371455758,
                    "dur": 0.00010395050048828125, "ema_dur": 0.0003155270629760326
                  },
                  …
                  "HEALTH": {
                    "alive": "yes",
                    "last_activity": {
                      "time": 1541773420.481246, "dt": 0.2783069610595703
                    }
                  },
                  "__doc__": {
                    "service.name.here": {
                      "count": "number of times the counter was called",
                      …
                    },
                    "HEALTH": {
                      "last_activity": {
                        "dt": "the minimum dt across all tracked counters",
                        …
                      },
                      "alive": {
                        "yes": "something was called within the last 60s",
                        …
                      }
                    }
                  }
                }
        '''
        r = { x: cls.dat[x].asdict for x in cls.dat }
        min_dt = min([ x['dt'] for x in r.values() ])
        max_t  = max([ x['last_t'] for x in r.values() ])
        h1 = {'time': max_t, 'dt': min_dt}
        r['HEALTH'] = h2 = {'last_activity': h1}
        r['__doc__'] = {
            'service.name.here': {
                "count": 'number of times the counter was called',
                "ema_dur": 'average duration of the calls',
                "dt": 'time since the last call of the counter',
                "ema_dt": 'average time between calls',
                "dur": 'duration of the last call',
                "last_t": 'the last time the counter was called',
            },
            'HEALTH': {
                "last_activity": {
                    "dt": 'the minimum dt across all tracked counters',
                    "time": 'the time of the most recent counter',
                },
                "alive": {
                        'yes': 'something was called within the last 60s',
                        'warn': 'something was called within the last 300s',
                        'hung': 'nothing has been called in 600s minutes',
                        'unknown': 'unknown — probably not a good sign though',
                },
            },
        }
        h2['alive'] = 'unknown'
        if h1['dt'] < 300:
            h2['alive'] = 'warn'
        if h1['dt'] >= 600:
            h2['alive'] = 'hung'
        if h1['dt'] < 60:
            h2['alive'] = 'yes'
        return r

    @classmethod
    def set_status_dumpster(cls, loc):
        global DUMPSTER
        DUMPSTER = loc
        if not cls._signaled:
            cls._signaled = True
            def dumpster_fire(signum, frame):
                try:
                    with open(DUMPSTER, 'w') as fh:
                        fh.write(json.dumps(cls.stats(), indent=2))
                        fh.write('\n')
                except:
                    log.exception("ignoring exception during dumpster fire")
            signal.signal(signal.SIGUSR1, dumpster_fire)
