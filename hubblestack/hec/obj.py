
import socket
import json
import time
import copy
import os

import certifi
import urllib3

import logging

from . dq import DiskQueue

__version__ = '1.0'

log = logging.getLogger('hubblestack.hec')

_max_content_bytes = 100000
http_event_collector_SSL_verify = True
http_event_collector_debug = False

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
    def promote(cls, payload, eventtime=''):
        if isinstance(payload, cls):
            return payload
        return Payload(payload, eventtime=eventtime)

    def __init__(self, dat, eventtime=''):
        if self.host is None:
            self.__class__.host = socket.gethostname()

        self.retries = Counter()

        if 'host' not in dat or dat['host'] is None:
            dat['host'] = self.host

        if eventtime:
            dat['time'] = eventtime
        elif 'time' not in dat:
            dat['time'] = str(int(time.time()))

        self.strip_empty_dict_entries(dat)
        self.dat = json.dumps(dat)

    def __repr__(self):
        return 'Payload({0})'.format(self)

    def __str__(self):
        return self.dat

    def __len__(self):
        return len(self.dat)

    @classmethod
    def strip_empty_dict_entries(cls, dat):
        todo = [dat]
        while todo:
            dat = todo.pop(0)
            if isinstance(dat, dict):
                remove_keys = [k for k in dat if not dat[k] and dat[k] not in (0,False) ]
                for k in remove_keys:
                    del dat[k]
                for v in dat.values():
                    if isinstance(v, (list,tuple,dict)):
                        if v not in todo:
                            todo.append(v)
            else:
                for item in dat:
                    if isinstance(item, (list,tuple,dict)):
                        if item not in todo:
                            todo.append(item)

# Thanks to George Starcher for the http_event_collector class (https://github.com/georgestarcher/)
# Default batch max size to match splunk's default limits for max byte
# See http_input stanza in limits.conf; note in testing I had to limit to
# 100,000 to avoid http event collector breaking connection Auto flush will
# occur if next event payload will exceed limit

class HEC(object):

    def __init__(self, token, http_event_server, host='', http_event_port='8088',
        http_event_server_ssl=True, max_bytes=_max_content_bytes, proxy=None, timeout=9.05,
        log_http_exceptions=False, log_other_exceptions=False):

        self.payload_retry_before_fail =  5
        self.queue_overflow_msg_delay = 10
        self.retry_diskqueue_interval = 60
        self._last_dq_flush_attempt = 0

        self.timeout = timeout
        self.token = token
        self.batchEvents = []
        self.maxByteLength = max_bytes
        self.currentByteLength = 0
        self.server_uri = []
        self.log_http_exceptions = log_http_exceptions
        self.log_other_exceptions = log_other_exceptions

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
                self.server_uri.append(['https://%s:%s/services/collector/event' % (server, http_event_port), True])
            else:
                self.server_uri.append(['http://%s:%s/services/collector/event' % (server, http_event_port), True])

        if http_event_collector_debug:
            print self.token
            print self.server_uri

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
                total=5, redirect=10, backoff_factor=3,
                connect=self.timeout, read=self.timeout,
                respect_retry_after_header=True)
        }

        if http_event_collector_SSL_verify:
            pm_kw.update({'cert_reqs': 'CERT_REQUIRED', 'ca_certs': certifi.where()})
        else:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if self.proxy:
            self.pool_manager = urllib3.ProxyManager(self.proxy, **pm_kw)
        else:
            self.pool_manager = urllib3.PoolManager(**pm_kw)

        self.queue = DiskQueue()

    def queueEvent(self, dat, eventtime=''):
        if not isinstance(dat, Payload):
            payload = Payload(dat, eventtime)
        self.queue.put(payload)

    def flushQueue(self):
        for i in self.queue:
            self.batchEvent(i)
        self.flushBatch()

    def _attempt_flush_queue(self):
        t = time.time()
        dt = t - self._last_dq_flush_attempt
        self._last_dq_flush_attempt = time.time()
        if dt >= self.retry_diskqueue_interval and self.queue.size:
            log.debug('flushing queue sz=%d', self.queue.size)
            self.flushQueue()

    def _requeue(self, payloads, server):
        server_maybe_bad = False
        for pload in payloads:
            pload.retries[ server ] += 1
            if pload.retries[ server ] < self.payload_retry_before_fail:
                self.queue.put(pload)
            else:
                server_maybe_bad = True
        return server_maybe_bad

    def _send(self, *payload):
        data = ' '.join([ str(x) for x in payload ])
        self.server_uri = [x for x in self.server_uri if x[1] is not False]
        for server in self.server_uri:
            try:
                r = self.pool_manager.request('POST', server[0], body=data, headers=self.headers)
            except urllib3.exceptions.LocationParseError as e:
                if self.log_other_exceptions:
                    log.error('server uri parse error "{0}": {1}'.format(server[0], e))
                server[1] = False
                continue
            except Exception as e:
                if self.log_other_exceptions:
                    log.error('Request to splunk threw an error: {0}'.format(e))
                server[1] = False
                continue
            if r.status >= 400:
                server_maybe_bad = self._requeue(payload, server[0])
                if server_maybe_bad:
                    if self.log_http_exceptions:
                        log.info('Request to splunk server "%s" failed. Marking as bad.' % server[0])
                    server[1] = False
                #self._requeue(self, payload, 'blah')
            else:
                return r

    def sendEvent(self, payload, eventtime=''):
        self._attempt_flush_queue()
        r = self._send( Payload.promote(payload, eventtime=eventtime) )

        if http_event_collector_debug:
            if r is not None and hasattr(r, 'text'):
                log.debug(r.text)
            log.debug(payload)


    def batchEvent(self, dat, eventtime=''):
        self._attempt_flush_queue()
        payload = Payload.promote(dat, eventtime)

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

http_event_collector = HEC
