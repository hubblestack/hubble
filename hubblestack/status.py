# -*- coding: utf-8 -*-
"""
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
"""

from functools import wraps
import time
import json
import signal
import logging
import os

log = logging.getLogger(__name__)

DEFAULTS = {
    'dumpster': 'status.json',  # '/var/cache/hubble/status.json',
    'hung_time': 900,
    'warn_time': 300,
    'good_time': 60,
    'bucket_len': 3600,
    'max_buckets': 3,
}


def t_bucket(timestamp=None, bucket_len=None):
    """ convert a time into a bucket id """
    if timestamp is None:
        timestamp = time.time()
    if bucket_len is None:
        bucket_len = int(get_hubble_status_opt('bucket_len'))
    timestamp = int(timestamp)
    seed = timestamp % bucket_len
    bucket = ((timestamp - seed), bucket_len)
    return bucket


__opts__ = dict()


def get_hubble_status_opt(name, require_type=None):
    """ try to locate HubbleStatus options in
        * __opts__['hubble_status'][name]
        * __opts__['hubble']['status'][name]
        * or __opts__['hubble_status_' + name]

        Various defaults are defined in hubblestack.status.DEFAULTS
    """
    for hubble_status_loc in (('hubble_status', name), ('hubble', 'status', name),
                              ('hubble_status_' + name)):
        opts = __opts__
        for k in hubble_status_loc:
            if isinstance(opts, dict):
                opts = opts.get(k)
        if opts is not None:
            break
    if opts is None:
        opts = DEFAULTS.get(name)
    if require_type and callable(require_type):
        try:
            opts = require_type(opts)
        except Exception:
            pass
    return opts



def get_hubble_or_salt_opt(name):
    """return the option specified by name found in __opts__ or __opts__['hubble'] """
    if name in __opts__:
        return __opts__[name]
    if 'hubble' in __opts__:
        if name in __opts__['hubble']:
            return __opts__['hubble'][name]
    return None



class HubbleStatusResourceNotFound(Exception):
    """ Exception caused by trying to mark() a counter that wasn't explicitly defined
    """
    pass


class ResourceTimer(object):
    """ described in HubbleStatus.resource_timer """

    def __init__(self, hubble_status, hs_key):
        self.hubble_status = hubble_status
        self.hs_key = hs_key

    def __enter__(self):
        self.hubble_status.mark(self.hs_key)

    def __exit__(self):
        self.hubble_status.fin(self.hs_key)


class HubbleStatus(object):
    """
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
    """
    _signaled = False
    dat = dict()
    resources = list()

    class Stat(object):
        """ Data sample container for a named mark.
            Stat objects have the following properties

            * first_t: the first time the counter was marked
            * last_t: the last time the counter was marked
            * count: the count of times the counter was marked
            * ema_dt: the average time between marks (updated at mark() time only)
            * dur: the duration of the last mark()/fin() cycle
            * ema_dur: the average duration between mark()/fin() cycles
        """

        def __init__(self, t=None):
            self.bucket, self.bucket_len = t_bucket(timestamp=t)
            self.next = None
            self.last_t = self.first_t = 0
            self.count = 0
            self.ema_dt = None
            self.dur = None
            self.ema_dur = None
            # reported is used exclusively by extmods/modules/hstatus
            # cleared on every mark()
            self.reported = list()

        def get_bucket(self, bucket, no_append=False):
            """ find the bucket with the `bucket` id and return it or append it to the list of
            buckets of the class """
            bucket, _ = t_bucket(timestamp=bucket)
            for i in self:
                if i.bucket == bucket:
                    return i
            new_bucket = self.__class__(t=bucket)
            if no_append:
                return new_bucket
            aux = self
            while aux.next is not None:
                aux = aux.next
            aux.next = new_bucket
            return new_bucket

        def find_bucket(self, bucket):
            """ return the bucket specified by the id `bucket` """
            return self.get_bucket(bucket, no_append=True)

        @property
        def dt(self):
            """ a computed attribute: the time since the last mark() """
            return time.time() - self.last_t

        @property
        def buckets(self):
            """ return a sorted set of the buckets """
            ret = {self.bucket, }
            if self.next is not None:
                ret.update(self.next.buckets)
            return sorted(ret)

        def asdict(self, bucket=None):
            """ return a copy of the various stat object properties
                (optionally for the given bucket)
            """
            if bucket is not None:
                self = self.find_bucket(bucket)
            ret = {'count': self.count, 'last_t': self.last_t,
                   'dt': self.dt, 'ema_dt': self.ema_dt, 'first_t': self.first_t,
                   'bucket': self.bucket, 'bucket_len': self.bucket_len}
            if self.dur is not None:
                ret.update({'dur': self.dur, 'ema_dur': self.ema_dur})
            return ret

        def mark(self, timestamp=None):
            """ mark a counter (ie, increment the count, mark the last_t =
                time.time(), and update the ema_dt)

                optional param "t": integer timestamp of mark
            """
            if timestamp is None:
                timestamp = time.time()
                self = self.get_bucket(timestamp)
            else:
                if isinstance(timestamp, str):
                    timestamp = int(timestamp)
                self = self.get_bucket(timestamp)
                if timestamp < self.first_t:
                    self.first_t = timestamp
                if timestamp > self.last_t:
                    self.last_t = timestamp
            if not self.first_t:
                self.first_t = timestamp
            self.count += 1
            last_mark = self.dt
            self.last_t = timestamp
            self.ema_dt = last_mark if self.ema_dt is None else 0.5 * self.ema_dt + 0.5 * last_mark
            self.reported = list()
            return self

        def fin(self):
            """ mark a counter duration (ie, mark the time since the last mark,
             and update the ema_dur)

                NOTE: because the stats are bucketed (for searching purposes),
                 it's important to fin() the right stat object.
                 For this reason, mark() returns a stat object, which is the right one upon
                 which to call fin()
            """
            self.dur = self.dt
            self.ema_dur = self.dur if self.ema_dur is None else 0.5 * self.ema_dur + 0.5 * self.dur

        def __iter__(self):
            if self.next is not None:
                for i in self.next:
                    yield i
            yield self

    def __init__(self, namespace, *resources):
        """ params:
            * namespace: a namespace for the counters tracked by the instance (usually __name__)
            * *resources: an argument list of names for counters tracked by the instance

            example:
                hs = HubbleStatus(__name__, 'process', 'top', 'gizmo')
                ...
                hs.mark('gizmo')
                long_operation()
                hs.dur('gizmo')
        """
        if namespace is None:
            namespace = '_'
        self.namespace = namespace
        if len(resources) == 1 and isinstance(resources[0], (list, tuple, dict)):
            resources = tuple(resources)
        for resource in resources:
            self.add_resource(resource)

    def add_resource(self, name):
        """ add the resource indentified by `name` to self.resources and self.dat if not present """
        res_id = self._namespaced(name)
        if res_id not in self.resources:
            self.resources.append(res_id)
        if res_id not in self.dat:
            self.dat[res_id] = self.Stat()

    def _namespaced(self, name):
        """ resolve `name` as a namespaced resource identifier
            e.g.: hs._namespaced('blah') → 'hubblestack.daemon.blah'
            prefixing is aborted if the argument `n` is already namespaced
        """
        if self.namespace is None or self.namespace.startswith('_'):
            return name
        if name.startswith(self.namespace + '.'):
            return name
        return self.namespace + '.' + name

    def _checkmark(self, resource):
        """ ensure the resource `resource` is tracked by the instance """
        res_id = self._namespaced(resource)
        if res_id not in self.resources:
            raise HubbleStatusResourceNotFound(
                '"{}" is not a resource of this HubbleStatus instance'.format(res_id))
        return res_id

    def _check_depth(self, resource):
        """ make sure we never have more than max_depth memory of past buckets """
        max_depth = int(get_hubble_status_opt('max_buckets'))
        resource = self._namespaced(resource)
        node = self.dat[resource]
        bucket_list = node.buckets
        if len(bucket_list) > max_depth:
            nb_list = sorted(node, key=lambda x: x.bucket)[-max_depth:]
            for idx, nb_node in enumerate(nb_list[:-1]):
                nb_node.next = nb_list[idx + 1]
            nb_list[-1].next = None
            self.dat[resource] = nb_list[0]

    def mark(self, resource, timestamp=None):
        """ mark the named resource `resource` — meaning increment the counters,
         update the last_t, etc """
        resource = self._checkmark(resource)
        ret = self.dat[resource].mark(timestamp=timestamp)
        self._check_depth(resource)
        return ret

    @classmethod
    def get_reported(cls, resource, bucket):
        """ return the reported list of the bucket `bucket` in the cls.dat[resource] """
        n_bucket = cls.dat[resource].find_bucket(bucket)
        if n_bucket:
            return n_bucket.reported
        return None

    @classmethod
    def buckets(cls, resource=None):
        """ return the sorted buckets for `resource`;
         if `resource` is None, return all the buckets in cls.dat """
        if resource is not None:
            return cls.dat[resource].buckets
        ret = set()
        for item in cls.dat.values():
            ret.update(item.buckets)
        return sorted(ret)

    def watch(self, mark_name):
        """ wrap a decorated function with a mark/fin pattern
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
        """
        invoke = False
        if callable(mark_name) and hasattr(mark_name, '__name__'):
            # if mark_name is actually a function, invoke the decorator
            # and return the decorated function (see below)
            invoke = mark_name
            mark_name = mark_name.__name__

        def decorator(func):
            """ decorator function that marks the counter and the counter duration """
            @wraps(func)
            def inner(*a, **kw):
                """ inner function returned by the decorator """
                stat_handle = self.mark(mark_name)
                ret = func(*a, **kw)
                stat_handle.fin()
                return ret
            return inner
        if invoke:
            return decorator(invoke)
        return decorator

    @classmethod
    def stats(cls):
        """ Produce a data structure suitable for output as json/yaml —
            intended to be invoked during SIGUSR1.

            The output includes a section (dict key/value) for each tracked
            counter, plus a section regards to the HEALTH of the system, and
            finally a __doc__ section that describes the values inline with the
            data.

            The output (after formatting as json) looks like the following
            (which was truncated and reordered slightly for presentation here).

            Estimated process health is guessed based on the timing information from the marks():

            The time spans hubble:status:hung_time=900 (past this time between marks,
             the process is probably hung)
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
        """

        stats_short = cls.short()

        min_dt = min([x['dt'] for x in stats_short.values()])
        max_t = max([x['last_t'] for x in stats_short.values()])
        min_t = min([x['first_t'] for x in stats_short.values() if x['first_t'] > 0])
        time_stats = {'time': max_t, 'dt': min_dt, 'start': min_t}
        stats_short['HEALTH'] = health_stats = {
            'buckets': {k: n.buckets for k, n in cls.dat.items()},
            'last_activity': time_stats,
        }
        stats_short['__doc__'] = {
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
        health_stats['alive'] = 'unknown'
        if time_stats['dt'] >= get_hubble_status_opt('hung_time'):
            health_stats['alive'] = 'hung'
        if time_stats['dt'] >= get_hubble_status_opt('warn_time'):
            health_stats['alive'] = 'warn'
        if time_stats['dt'] <= get_hubble_status_opt('good_time'):
            health_stats['alive'] = 'yes'
        return stats_short

    @classmethod
    def short(cls, bucket=None):
        """ return a shortened stats listing (no docs or health guesses)

            optionally, give parameter bucket:
                some number in epoch time - to return the stats in that bucket
                or the word 'all' or the string '*' - to return all but the
                  last bucket as a list

        """
        if bucket in ('*', 'all'):
            return [cls.short(b) for b in cls.buckets()]
        return {k: v.asdict(bucket) for k, v in cls.dat.items() if v.first_t > 0}

    @classmethod
    def as_json(cls, indent=2):
        """ return the stats as json with customizable indent size"""
        return json.dumps(cls.stats(), indent=indent)

    @classmethod
    def dumpster_fire(cls, *_a, **_kw):
        """ dump the status.json file to cachedir

            Location and filename can be adjusted with the cachedir and
            hubble:status:dumpster options (see above).
        """
        try:
            if __salt__['config.get']('splunklogging', False):
                # lazy load to avoid circular import
                import hubblestack.log
                hubblestack.log.emit_to_splunk('Signal {0} detected'.format(signal.SIGUSR1),
                                               'INFO',
                                               'hubblestack.signals')
        finally:
            dumpster = get_hubble_status_opt('dumpster') or 'status.json'
            if not dumpster.startswith('/'):
                cachedir = get_hubble_or_salt_opt('cachedir') or '/tmp'
                dumpster = os.path.join(cachedir, dumpster)
            try:
                with open(dumpster, 'w') as status_file:
                    status_file.write(cls.as_json())
                    status_file.write('\n')
                log.info("wrote HubbleStatus to %s", dumpster)
            except Exception:
                log.exception("ignoring exception during dumpster fire")

    @classmethod
    def start_sigusr1_signal_handler(cls):
        """ start the signal.SIGUSR1 handler (dumps status to
            /var/cache/hubble/status.json or whatever is specified in
            cachedir + hubble:status:dumpster configs)
        """
        if not cls._signaled:
            cls._signaled = True
            if not hasattr(signal, 'SIGUSR1'):
                # TODO: invent invocation that works in windows instead of just complaining
                log.info("signal package lacks SIGUSR1, skipping SIGUSR1 status.json handler setup")
                return
            signal.signal(signal.SIGUSR1, cls.dumpster_fire)

    def resource_timer(self, hs_key):
        """ return an object suitable for a with-block for timing code

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
        """
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
