# -*- coding: utf-8 -*-
'''
hubblestack.status aims to be a very lightweight stats tracker for the purposes
of verifying the health of daemon. It piggybacks the normal hubble operations,
increments counters, tracks function call times (and averages), and can dump to
a status file on request.

.. code-block:: shell
    sudo pkill -10 hubble
    echo -n hubble alive:
    sudo cat /var/cache/hubble/status.json | jq -r .HEALTH.alive

hubblestack.status options:

    hubble:status:dumpster
        The filename for the status dump (default: status.json).  If the
        filename begins with a '/', the filename is assumed to be a full
        pathname otherwise, the file will be placed in the hubble `cachedir`.

    hubble:status:hung_time
        If no counters have advanced or updated in (default) 900s, then the status dump will report
        hubble as being "hung."

    hubble:status:warn_time
        If no counters have advanced or updated in (default) 300s, then the status dump will report
        hubble as being "warn."

    hubble:status:good_time
        If any counter has advanced or updated in the last (default) 60s, then
        the status dump will report the status as "yes."
'''

from collections import namedtuple
from functools import wraps
import time
import json
import signal
import logging
import os

log = logging.getLogger(__name__)

DEFAULTS = {
    'dumpster': 'status.json', # '/var/cache/hubble/status.json',
    'hung_time': 900,
    'warn_time': 300,
    'good_time':  60,
}

__opts__ = dict()
def get_hubble_status_opt(name, require_type=None):
    ''' try to locate HubbleStatus options in
        * __opts__['hubble_status'][name]
        * __opts__['hubble']['status'][name]
        * or __opts__['hubble_status_' + name]

        Various defaults are defined in hubblestack.status.DEFAULTS
    '''
    r = None
    for kl in (('hubble_status',name), ('hubble','status',name), ('hubble_status_'+name)):
        t = __opts__
        for k in kl:
            if isinstance(t, dict):
                t = t.get(k)
        if t is not None:
            r = t
            break
    if t is None:
        t = DEFAULTS.get(name)
    if require_type and callable(require_type):
        try:
            t = require_type(t)
        except:
            pass
    return t

def get_hubble_or_salt_opt(name):
    if name in __opts__:
        return __opts__[name]
    if 'hubble' in __opts__:
        if name in __opts__['hubble']:
            return __opts__['hubble'][name]

class HubbleStatusResourceNotFound(Exception):
    ''' Exception caused by trying to mark() a counter that wasn't explicitly defined
    '''
    pass

class ResourceTimer(object):
    ''' described in HubbleStatus.resource_timer '''
    def __init__(self, hubble_status, hs_key):
        self.hubble_status = hubble_status
        self.hs_key = hs_key

    def __enter__(self):
        self.hubble_status.mark(self.hs_key)

    def __exit__(self):
        self.hubble_status.fin(self.hs_key)

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
    resources = list()
    class Stat(object):
        ''' Data sample container for a named mark.
            Stat objects have the following properties

            * first_t: the first time the counter was marked
            * last_t: the last time the counter was marked
            * count: the count of times the counter was marked
            * ema_dt: the average time between marks (updated at mark() time only)
            * dur: the duration of the last mark()/fin() cycle
            * ema_dur: the average duration between mark()/fin() cycles
        '''

        def __init__(self):
            self.reset()

        @property
        def dt(self):
            ''' a computed attribute: the time since the last mark() '''
            return time.time() - self.last_t

        @property
        def asdict(self):
            ''' a computed attribute that clones and formats the various object properties in a dict() '''
            r = { 'count': self.count, 'last_t': self.last_t,
                'dt': self.dt, 'ema_dt': self.ema_dt, 'first_t': self.first_t }
            if self.dur is not None:
                r.update({'dur': self.dur, 'ema_dur': self.ema_dur})
            return r

        def mark(self, t=None):
            ''' mark a counter (ie, increment the count, mark the last_t =
                time.time(), and update the ema_dt)
            '''
            now = time.time()
            if not self.first_t:
                self.first_t = now
            self.count += 1
            dt = self.dt
            self.last_t = now
            if t is not None:
                # NOTE: t should only be used for tracking time constrained counts
                # (e.g., the sourcetype counts in hec.obj); we make sure the first_t
                # and last_t include the given (e.g.) event time
                if isinstance(t, str):
                    t = int(t)
                if t < self.first_t:
                    self.first_t = t
                if t > self.last_t:
                    self.last_t = t
            self.ema_dt = dt if self.ema_dt is None else 0.5*self.ema_dt + 0.5*dt

        def fin(self):
            ''' mark a counter duration (ie, mark the time since the last mark, and update the ema_dur)
            '''
            self.dur = self.dt
            self.ema_dur  = self.dur if self.ema_dur is None else 0.5*self.ema_dur + 0.5*self.dur

        def reset(self):
            self.last_t = self.first_t = 0
            self.count  = 0
            self.ema_dt = None
            self.dur = None
            self.ema_dur = None


    def __init__(self, namespace, *resources):
        ''' params:
            * namespace: a namespace for the counters tracked by the instance (usually __name__)
            * *resources: an argument list of names for counters tracked by the instance

            example:
                hs = HubbleStatus(__name__, 'process', 'top', 'gizmo')
                ...
                hs.mark('gizmo')
                long_operation()
                hs.dur('gizmo')
        '''
        if namespace is None:
            namespace = '_'
        self.namespace = namespace
        if len(resources) == 1 and isinstance(resources[0], (list,tuple,dict)):
            resources = tuple(resources)
        for r in resources:
            self.add_resource(r)

    def add_resource(self, name):
        r = self._namespaced(name)
        if r not in self.resources:
            self.resources.append(r)
        if r not in self.dat:
            self.dat[r] = self.Stat()

    def _namespaced(self, n):
        ''' resolve `n` as a namespaced resource identifier
            e.g.: hs._namespaced('blah') → 'hubblestack.daemon.blah'
            prefixing is aborted if the argument `n` is already namespaced
        '''
        if self.namespace is None or self.namespace.startswith('_'):
            return n
        if n.startswith(self.namespace + '.'):
            return n
        return self.namespace + '.' + n

    def _checkmark(self, n):
        ''' ensure the resource `n` is tracked by the instance '''
        m = self._namespaced(n)
        if m not in self.resources:
            raise HubbleStatusResourceNotFound('"{}" is not a resource of this HubbleStatus instance')
        return m

    def mark(self, n, t=None):
        ''' mark the named resource `n` — meaning increment the counters, update the last_t, etc '''
        n = self._checkmark(n)
        self.dat[n].mark(t=t)

    def fin(self, n):
        ''' mark the end of a duration measurement '''
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
                r = f(*a, **kw)
                self.fin(mark_name)
                return r
            return inner
        if invoke:
            return decorator(invoke)
        return decorator

    @classmethod
    def reset(cls, key=None):
        # NOTE: this is janky... allowing resets on arbitrary keys on the
        # class, not even tracked with _checkmark() ... but it's needed to make
        # the sourcetype accounting beacon update meaningfully.
        if key is None:
            for key in cls.dat:
                cls.dat[key].reset()
        else:
            cls.dat[key].reset()

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

            Estimated process health is guessed based on the timing information from the marks():

            The time spans hubble:status:hung_time=900 (past this time between marks, the process is probably hung)
            all configurable: hubble:status:hung_time


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
        r = { k: v.asdict for k,v in cls.dat.iteritems() if v.first_t > 0 }
        min_dt = min([ x['dt'] for x in r.values() ])
        max_t  = max([ x['last_t'] for x in r.values() ])
        min_t  = min([ x['first_t'] for x in r.values() if x['first_t'] > 0 ])
        h1 = {'time': max_t, 'dt': min_dt, 'start': min_t}
        r['HEALTH'] = h2 = {'last_activity': h1}
        r['__doc__'] = {
            'service.name.here': {
                "count": 'number of times the counter was called',
                "ema_dur": 'average duration of the calls',
                "dt": 'time since the last call of the counter',
                "ema_dt": 'average time between calls',
                "dur": 'duration of the last call',
                "last_t": 'the last time the counter was called',
                "first_t": 'the first time the counter was called',
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
        if h1['dt'] >= get_hubble_status_opt('hung_time'):
            h2['alive'] = 'hung'
        if h1['dt'] >= get_hubble_status_opt('warn_time'):
            h2['alive'] = 'warn'
        if h1['dt'] <= get_hubble_status_opt('good_time'):
            h2['alive'] = 'yes'
        return r

    @classmethod
    def as_json(cls, indent=2):
        return json.dumps(cls.stats(), indent=indent)

    @classmethod
    def dumpster_fire(cls, *a, **kw):
        ''' dump the status.json file to cachedir

            Location and filename can be adjusted with the cachedir and
            hubble:status:dumpster options (see above).
        '''
        dumpster = get_hubble_status_opt('dumpster') or 'status.json'
        if not dumpster.startswith('/'):
            cachedir = get_hubble_or_salt_opt('cachedir') or '/tmp'
            dumpster = os.path.join(cachedir, dumpster)
        try:
            with open(dumpster, 'w') as fh:
                fh.write(cls.as_json())
                fh.write('\n')
            log.info("wrote HubbleStatus to %s", dumpster)
        except:
            log.exception("ignoring exception during dumpster fire")

    @classmethod
    def start_sigusr1_signal_handler(cls):
        ''' start the signal.SIGUSR1 handler (dumps status to
            /var/cache/hubble/status.json or whatever is specified in
            cachedir + hubble:status:dumpster configs)
        '''
        if not cls._signaled:
            cls._signaled = True
            if not hasattr(signal, 'SIGUSR1'):
                # TODO: invent invocation that works in windows instead of just complaining
                log.info("signal package lacks SIGUSR1, skipping SIGUSR1 status.json handler setup")
                return
            signal.signal(signal.SIGUSR1, cls.dumpster_fire)

    def resource_timer(self, hs_key):
        ''' return an object suitable for a with-block for timing code

            instead of writing:
                hs_key = 'resource-name-here'
                hubble_status.add_resource(hs_key)
                hubble_status.mark(hs_key)
                do_things()
                do_other_things()
                hubble_status.fin(hs_key)

            write this:
                with hubble_status.resource_timer('resource-name-here'):
                    do_things()
                    do_other_things()
        '''
        self.add_resource(hs_key)
        return ResourceTimer(self, hs_key)

def _setup_for_testing():
    global __opts__
    import hubblestack.daemon
    parsed_args = hubblestack.daemon.parse_args()
    import salt.config
    parsed_args['configfile'] = config_file = '/etc/hubble/hubble'
    __opts__ = salt.config.minion_config(config_file)
    __opts__['conf_file'] = config_file
    __opts__.update(parsed_args)
    import salt.loader
    __grains__ = salt.loader.grains(__opts__)
