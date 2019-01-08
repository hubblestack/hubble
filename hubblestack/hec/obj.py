# -*- encoding: utf-8 -*-

import socket
import json
import time
import copy
import os
import hashlib

import certifi
import urllib3

from . dq import DiskQueue, QueueCapacityError

import logging
log = logging.getLogger(__name__)

__version__ = '1.0'

_max_content_bytes = 100000
http_event_collector_debug = False

# the list of collector URLs given to the HEC object
# are hashed into an md5 string that identifies the URL set
# these maximums are per URL set, not for the entire disk cache
max_diskqueue_size  = 10 * (1024 ** 2)

class Payload(object):
    ''' formatters for final payload stringification
        and a convenient place to store retry counter information

        note that formatting a payload is different from formatting an event
        say our event is a line like
          "Sat Aug 18 ProcessName [3828282] DEBUG: oops"
        or perhaps some data like
          {'blah': 'happened"}
        Then the payload would look like this:
          {'host': 'something', 'sourcetype': 'something', 'event': 'Sat Aug 18...'}
          {'host': 'something', 'sourcetype': 'something', 'event': {'blah': 'happened'}}

        For reasons regarding the above, we provide a classmethod to format events:

        p = Payload.format_event({'blah': 'happened'}, sourcetype='blah')
    '''
    host = None

    @classmethod
    def format_event(cls, event, **payload):
        if 'host' not in payload:
            payload['host'] = cls.host
        if 'sourcetype' not in payload:
            payload['sourcetype'] = 'hubble'
        payload['event'] = event
        return cls(payload)

    @classmethod
    def promote(cls, payload, eventtime='', no_queue=False):
        if isinstance(payload, cls):
            return payload
        return Payload(payload, eventtime=eventtime, no_queue=no_queue)

    def __init__(self, dat, eventtime='', no_queue=False):
        if self.host is None:
            self.__class__.host = socket.gethostname()

        self.requeues = 0
        self.no_queue = no_queue or dat.pop('_no_queue', False)

        if 'host' not in dat or dat['host'] is None:
            dat['host'] = self.host

        if eventtime:
            dat['time'] = eventtime
        elif 'time' not in dat:
            dat['time'] = str(int(time.time()))

        self.rename_event_fields_in_payload(dat)
        self.dat = json.dumps(dat)

    def __repr__(self):
        return 'Payload({0})'.format(self)

    def __str__(self):
        return self.dat

    def __len__(self):
        return len(self.dat)

    @classmethod
    def rename_event_fields_in_payload(cls, dat):
        f = dat.get('fields')
        e = dat.get('event')
        if isinstance(f, dict) and isinstance(e, dict):
            for k in f:
                v = e.pop(k)
                if v is not None:
                    e[k + '_meta'] = v


# Thanks to George Starcher for the http_event_collector class (https://github.com/georgestarcher/)
# Default batch max size to match splunk's default limits for max byte
# See http_input stanza in limits.conf; note in testing I had to limit to
# 100,000 to avoid http event collector breaking connection Auto flush will
# occur if next event payload will exceed limit

class HEC(object):
    flushing_queue = False
    last_flush = 0

    class Server(object):
        bad = False
        def __init__(self, host, port=8080, proto='https'):
            if '://' in host:
                proto,host = host.split('://')
            if ':' in host:
                host,port = host.split(':')
            self.uri = '{proto}://{host}:{port}/services/collector/event'.format(
                proto=proto, host=host, port=port)
            self.fails = 0

        def __str__(self):
            r = self.uri
            if self.fails:
                r += ' (fails: {0})'.format(self.fails)
            return r


    def __init__(self, token, http_event_server, host='', http_event_port='8088',
                 http_event_server_ssl=True, http_event_collector_ssl_verify=True,
                 max_bytes=_max_content_bytes, proxy=None, timeout=9.05,
                 disk_queue=False,
                 disk_queue_size=max_diskqueue_size,
                 disk_queue_compression=5):

        self.max_requeues =  5
        self.retry_diskqueue_interval = 60

        self.timeout = timeout
        self.token = token
        self.batchEvents = []
        self.maxByteLength = max_bytes
        self.currentByteLength = 0
        self.server_uri = []

        if proxy and http_event_server_ssl:
            self.proxy = {'https': 'https://{0}'.format(proxy)}
        elif proxy:
            self.proxy = {'http': 'http://{0}'.format(proxy)}
        else:
            self.proxy = {}

        # Set host to specified value or default to localhostname if no value provided
        if host:
            self.host = host
        else:
            self.host = socket.gethostname()

        Payload.host = self.host

        # Build and set server_uri for http event collector
        # Defaults to SSL if flag not passed
        # Defaults to port 8088 if port not passed

        servers = http_event_server
        if not isinstance(servers, list):
            servers = [servers]
        for server in servers:
            if http_event_server_ssl:
                self.server_uri.append(self.Server(server, http_event_port, proto='https'))
            else:
                self.server_uri.append(self.Server(server, http_event_port, proto='http'))

        # build headers once
        self.headers = urllib3.make_headers( keep_alive=True,
            user_agent='hubble-hec/{0}'.format(__version__),
            accept_encoding=True)
        self.headers.update({ 'Content-Type': 'application/json',
            'Authorization': 'Splunk {0}'.format(self.token) })

        # retries can be made much more flexible than shown here theoretically,
        # it could take the load off overloaded servers through the backoff and
        # improve overall throughput at those (usually transient) bottlenecks
        # -- the number 3 was chosen essentially at random
        pm_kw = {
            'timeout': self.timeout,
            'retries': urllib3.util.retry.Retry(
                total=3, redirect=10, backoff_factor=3,
                connect=self.timeout, read=self.timeout,
                respect_retry_after_header=True)
        }

        if http_event_collector_ssl_verify:
            pm_kw.update({'cert_reqs': 'CERT_REQUIRED', 'ca_certs': certifi.where()})
        else:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if self.proxy:
            self.pool_manager = urllib3.ProxyManager(self.proxy, **pm_kw)
        else:
            self.pool_manager = urllib3.PoolManager(**pm_kw)

        if disk_queue:
            md5 = hashlib.md5()
            uril = sorted([ x.uri for x in self.server_uri ])
            for u in uril:
                md5.update(u)
            actual_disk_queue = os.path.join(disk_queue, md5.hexdigest())
            log.debug("disk_queue for %s: %s", uril, actual_disk_queue)
            self.queue = DiskQueue(actual_disk_queue, size=disk_queue_size, compression=disk_queue_compression)
        else:
            class NoQueue(object):
                cn = 0
                def put(self, *a, **kw):
                    log.debug('no-queue.put() dumping event')
                    pass
                def getz(self, *a, **kw):
                    log.debug('no-queue.put() nothing to dequeue')
                    pass

    def _queue_event(self, payload):
        try:
            self.queue.put(str(payload))
        except QueueCapacityError:
            log.info("disk queue is full, dropping payload")


    def queueEvent(self, dat, eventtime=''):
        if not isinstance(dat, Payload):
            dat = Payload(dat, eventtime, no_queue=no_queue)
        if dat.no_queue: # here you silly hec, queue this no_queue payload...
            return
        self._queue_event(dat)


    def flushQueue(self):
        if self.flushing_queue:
            log.debug('already flushing queue')
            return
        if self.queue.cn < 1:
            log.debug('nothing in queue')
            return
        dt = time.time() - self.last_flush
        if dt >= self.retry_diskqueue_interval and self.queue.cn:
            log.debug('flushing queue eventscount=%d', self.queue.cn)
        self.last_flush = time.time()
        self.flushing_queue = True
        while self.flushing_queue:
            x = self.queue.getz()
            if not x:
                break
            self._send(x)
        self.flushing_queue = False


    def _requeue(self, payloads):
        log.debug("_requeue")
        if self.flushing_queue:
            log.debug("aborting queue flush due to requeue")
            self.flushing_queue = False
        if not isinstance(payloads, (list,tuple)):
            payloads = [ payloads ]
        for pload in payloads:
            if pload.no_queue:
                continue
            if pload.requeues < self.max_requeues:
                log.debug("requeueing payload (requeues so far: %d)", pload.requeues)
                pload.requeues += 1
                self._queue_event(pload)


    def _send(self, *payload):
        data = ' '.join([ str(x) for x in payload ])

        servers = [ x for x in self.server_uri if not x.bad ]
        if not servers:
            log.error("all servers are marked 'bad', aborting send")
            return

        # This logic is overly complicated originally the plan was to have the
        # HEC() object manage multiple servers and choose the successful one to
        # send to. Mostly if the hubble configs contain multiple endpoints,
        # hubble sends to all of them, not just the first successful one.  and
        # mostly that logic is handled outside of the HEC class (see
        # splunklogging.py)
        for server in sorted(servers, key=lambda u: u.fails):
            try:
                r = self.pool_manager.request('POST', server.uri, body=data, headers=self.headers)
                server.fails = 0
            except urllib3.exceptions.LocationParseError as e:
                log.error('server uri parse error "%s": %s', server.uri, e)
                server.bad = True
                continue
            except Exception as e:
                log.error('presumed minor error with "%s" (mark fail and continue): %s', server.uri, e)
                server.fails += 1
                continue
            if r.status < 400:
                return r
            elif r.status == 400 and r.reason.lower() == 'bad request':
                log.error('message not accepted (%d %s), dropping payload: %s', r.status, r.reason, r.data)
                return r

        log.error('message not accepted (%d %s), requeueing: %s', r.status, r.reason, r.data)
        self._requeue(payload)

    def _finish_send(self, r):
        if r is not None and hasattr(r, 'status') and hasattr(r, 'reason'):
            log.debug('_send() result: %d %s', r.status, r.reason)
            self.flushQueue()


    def sendEvent(self, payload, eventtime='', no_queue=False):
        r = self._send( Payload.promote(payload, eventtime=eventtime, no_queue=no_queue) )
        self._finish_send(r)


    def batchEvent(self, dat, eventtime='', no_queue=False):
        payload = Payload.promote(dat, eventtime, no_queue=False)

        if (self.currentByteLength + len(payload)) > self.maxByteLength:
            self.flushBatch()
            if http_event_collector_debug:
                log.debug('auto flushing')
        else:
            self.currentByteLength = self.currentByteLength + len(payload)
        self.batchEvents.append(payload)


    def flushBatch(self):
        if self.batchEvents:
            r = self._send( *self.batchEvents )
            self.batchEvents = []
            self.currentByteLength = 0
            self._finish_send(r)

http_event_collector = HEC
