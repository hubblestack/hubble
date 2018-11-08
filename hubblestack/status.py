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
            r = { 'start': self.start, 'count': self.count, 'last_t': self.last_t,
                'dt': self.dt, 'ema_dt': self.ema_dt }
            if self.dur is not None:
                r.update({'dur': self.dur, 'ema_dur': self.ema_dur})
            return r

        def mark(self):
            t = time.time()
            self.count += 1
            dt = self.dt
            self.last_t = t
            self.ema_dt  = dt if self.ema_dt is None else 0.5*self.ema_dt + 0.5*dt

        def fin(self):
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
        r = { x: cls.dat[x].asdict for x in cls.dat }
        min_dt = min([ x['dt'] for x in r.values() ])
        max_t  = max([ x['last_t'] for x in r.values() ])
        h1 = {'time': max_t, 'dt': min_dt}
        r['HEALTH'] = h2 = {'last_activity': h1}
        h2['alive'] = 'unknown'
        if h1['dt'] < 300:
            h2['alive'] = 'probably ok'
        if h1['dt'] >= 600:
            h2['alive'] = 'possibly hung'
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
