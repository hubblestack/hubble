import time
import json
from collections import namedtuple

class HubbleStatusResourceNotFound(Exception):
    pass

class HubbleStatus(object):
    dat = dict()
    class Stat(object):
        def __init__(self):
            self.last_t = self.start = time.time()
            self.count  = 0
            self.ema_dt = None
            self.ema_var = None

        @property
        def dt(self):
            return time.time() - self.last_t

        @property
        def asdict(self):
            return { 'start': self.start, 'count': self.count, 'dt': self.dt,
                'ema_dt': self.ema_dt, 'ema_var': self.ema_var }

        def mark(self):
            t = time.time()
            self.count += 1
            dt = self.dt
            self.last_t = t
            self.ema_dt  = dt if self.ema_dt is None else 0.5*self.ema_dt + 0.5*dt
            var = (self.ema_dt - dt) ** 2
            self.ema_var = var if self.ema_var is None else 0.5*self.ema_var + 0.5*var

    def __init__(self, namespace, *resources):
        if namespace is None:
            namespace = '_'
        self.namespace = namespace
        if len(resources) == 1 and isinstance(resources[0], (list,tuple,dict)):
            resources = tuple(resources)
        self.resources = [ self._namespaced(x) for x in resources ]
        for r in self.resources:
            self.dat[r] = self.Stat()

    @property
    def stats(self):
        return { x: self.dat[x].asdict for x in self.dat }

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

    @property
    def asdict(self):
        return { x: self.dat[x].asdict for x in self.dat }
