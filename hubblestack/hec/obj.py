# -*- encoding: utf-8 -*-

import socket
import json
import time
import copy
import os
import hashlib

import certifi
import urllib3

import logging
log = logging.getLogger(__name__)

import hubblestack.status
hubble_status = hubblestack.status.HubbleStatus(__name__)

from . dq import DiskQueue, NoQueue, QueueCapacityError
from inspect import getfullargspec
from hubblestack.utils.stdrec import update_payload
from hubblestack.utils.encoding import encode_something_to_bytes

__version__ = '1.0'

_max_content_bytes = 100000
http_event_collector_debug = False

# the list of collector URLs given to the HEC object
# are hashed into an md5 string that identifies the URL set
# these maximums are per URL set, not for the entire disk cache
max_diskqueue_size  = 10 * (1024 ** 2)
isFipsEnabled = True if 'usedforsecurity' in getfullargspec(hashlib.new).kwonlyargs else False


def count_input(payload):
    hs_key = ':'.join(['input', payload.sourcetype])
    hubble_status.add_resource(hs_key)
    hubble_status.mark(hs_key, timestamp=payload.time)
    # NOTE: t=payload.time is an undocumented mark() argument
    # that ensures the first_t and last_t include the given timestamp
    # (without this, the accounting likely wouldn't work)

class Payload(object):
    """ formatters for final payload stringification
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
    """
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

        self.no_queue = no_queue or dat.pop('_no_queue', False)

        if 'host' not in dat or dat['host'] is None:
            dat['host'] = self.host

        now = time.time()
        if eventtime:
            dat['time'] = eventtime
        elif 'time' not in dat:
            dat['time'] = now

        self.sourcetype = dat.get('sourcetype', 'hubble')
        self.time       = dat.get('time', now)

        self.dat = json.dumps(dat)

    def __repr__(self):
        return 'Payload({0})'.format(self)

    def __str__(self):
        return self.dat

    def __len__(self):
        return len(self.dat)


class OutageInfo(object):
    def __init__(self):
        self.last_check = self.start = time.time()

    def checking(self):
        self.last_check = time.time()

    @property
    def last_check_age(self):
        return time.time() - self.last_check

    @property
    def age(self):
        return time.time() - self.start

# Thanks to George Starcher for the http_event_collector class (https://github.com/georgestarcher/)
# Default batch max size to match splunk's default limits for max byte
# See http_input stanza in limits.conf; note in testing I had to limit to
# 100,000 to avoid http event collector breaking connection Auto flush will
# occur if next event payload will exceed limit

class HEC(object):
    last_flush = 0
    flushing_queue = False
    abort_flush    = False
    direct_logging = False
    outages = dict()
    fails = dict()

    class Server(object):
        bad = False

        def __init__(self, host, port=8080, proto='https'):
            if '://' in host:
                proto,host = host.split('://')
            if ':' in host:
                host,port = host.split(':')
            self.uri = '{proto}://{host}:{port}/services/collector/event'.format(
                proto=proto, host=host, port=port)
            if self.uri not in HEC.fails:
                HEC.fails[self.uri] = 0

        @property
        def fails(self):
            return HEC.fails[self.uri]

        @fails.setter
        def fails(self, v):
            HEC.fails[self.uri] = v

        def __str__(self):
            r = self.uri
            if self.fails:
                r += ' (fails: {0})'.format(self.fails)
            return r

        @property
        def outage(self):
            if self.uri in HEC.outages:
                return HEC.outages.get(self.uri)

        @outage.setter
        def outage(self, v):
            if v:
                HEC.outages[self.uri] = OutageInfo()
            elif self.uri in HEC.outages:
                del HEC.outages[self.uri]
                self.fails = 0


    def __init__(self, token, index, http_event_server, host='', http_event_port='8088',
                 http_event_server_ssl=True, http_event_collector_ssl_verify=True,
                 max_bytes=_max_content_bytes, proxy=None, timeout=9.05,
                 disk_queue=False, disk_queue_size=max_diskqueue_size,
                 disk_queue_compression=5, max_queue_cycles=80, max_bad_request_cycles=40,
                 outage_recheck_time=300, num_fails_indicate_outage=10):


        self.max_queue_cycles = max_queue_cycles
        self.max_bad_request_cycles = max_bad_request_cycles
        self.outage_recheck_time = outage_recheck_time
        self.num_fails_indicate_outage = num_fails_indicate_outage

        self.retry_diskqueue_interval = 60

        self.timeout = timeout
        self.token = token
        self.default_index = index
        self.batchEvents = []
        self.maxByteLength = max_bytes
        self.currentByteLength = 0
        self.server_uri = []

        if proxy and http_event_server_ssl:
            self.proxy = 'https://{0}'.format(proxy)
        elif proxy:
            self.proxy = 'http://{0}'.format(proxy)
        else:
            self.proxy = None

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

        # 2019-09-24: lowered retries from 3 (9s + 3*9s = 36s) to 1 (9s + 9s = 18s)
        # Each new event could potentially take half a minute with 3 retries.
        # Since Hubble is single threaded, that seems like a horribly long time.
        # (When retries fail, we potentially queue to disk anyway.)
        pm_kw = {
            'timeout': self.timeout,
            'retries': urllib3.util.retry.Retry(
                total=1,   # total retries; overrides other counts below
                connect=3, # number of retires on connection errors
                read=3,    # number of retires on read errors
                status=3,  # number of retires on bad status codes
                redirect=10, # avoid redirect loops by limiting redirects to 10
                respect_retry_after_header=True)
        }

        if http_event_collector_ssl_verify:
            pm_kw.update({'cert_reqs': 'CERT_REQUIRED', 'ca_certs': certifi.where()})
        else:
            pm_kw.update({'cert_reqs': 'CERT_NONE'})
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if self.proxy:
            self.pool_manager = urllib3.ProxyManager(self.proxy, **pm_kw)
        else:
            self.pool_manager = urllib3.PoolManager(**pm_kw)

        if disk_queue:
            if isFipsEnabled:
                md5 = hashlib.md5(usedforsecurity=False)
            else:
                md5 = hashlib.md5()
            uril = sorted([ x.uri for x in self.server_uri ])
            for u in uril:
                md5.update(encode_something_to_bytes(u))
            actual_disk_queue = os.path.join(disk_queue, md5.hexdigest())
            log.debug("disk_queue for %s: %s", uril, actual_disk_queue)
            self.queue = DiskQueue(actual_disk_queue, size=disk_queue_size, compression=disk_queue_compression)
        else:
            self.queue = NoQueue()

    def _payload_msg(self, message, *a):
        event = dict(loggername='hubblestack.hec.obj', message=message % a)
        payload = dict(index=self.default_index,
            time=int(time.time()), sourcetype='hubble_log', event=event)
        update_payload(payload)
        return str(Payload(payload))

    def _direct_send_msg(self, message, *a):
        self._send(self._payload_msg(message, *a))

    def _queue_event(self, payload, meta_data=None):
        if HEC.flushing_queue:
            HEC.abort_flush = True
        if self.queue.cn < 1 and not HEC.direct_logging:
            HEC.direct_logging = True
            self._direct_send_msg('queue(start)')
            HEC.direct_logging = False
        p = str(payload)
        # should be at info level; error for production logging:
        log.error('Sending to Splunk failed, queueing %d octets to disk', len(p))
        try:
            if meta_data is None:
                meta_data = dict()
            if 'queued_to_disk' not in meta_data:
                meta_data['queued_to_disk'] = 0
            meta_data['queued_to_disk'] += 1
            log.debug(' meta_data: %s', meta_data)
            self.queue.put(p, **meta_data)
        except QueueCapacityError:
            # was at info level, but this is an error condition worth logging
            log.error("disk queue is full, dropping payload")


    def queueEvent(self, dat, eventtime='', no_queue=False):
        if not isinstance(dat, Payload):
            dat = Payload(dat, eventtime, no_queue=no_queue)
        if dat.no_queue: # here you silly hec, queue this no_queue payload...
            return
        count_input(dat)
        self._queue_event(dat)

    def flushQueue(self):
        if HEC.flushing_queue:
            log.debug('already flushing queue')
            return
        if self.queue.cn < 1:
            log.debug('nothing in queue')
            return
        HEC.flushing_queue = True
        HEC.abort_flush = False
        self._direct_send_msg('queue(flush) eventscount=%d', self.queue.cn)
        dt = time.time() - HEC.last_flush
        if dt >= self.retry_diskqueue_interval and self.queue.cn:
            # was at debug level. bumped to error level for production logging
            log.error('flushing queue eventscount=%d; NOTE: queued events may contain more than one payload/event',
                self.queue.cn)
        HEC.last_flush = time.time()
        while HEC.flushing_queue:
            x, meta_data = self.queue.getz()
            if not x:
                break
            log.debug('pulled %d octets from queue; meta_data: %s', len(x), meta_data)
            self._send(x, meta_data=meta_data)
            if HEC.abort_flush:
                log.error('aborting flush (probably due to new queue item)')
                break
        HEC.flushing_queue = False
        if self.queue.cn < 1:
            self._direct_send_msg('queue(end)')
            log.error('flushing complete eventscount=%d', self.queue.cn)


    def _send(self, *payload, **kwargs):
        now = time.time()
        data = ' '.join([ str(x) for x in payload ])

        servers = [ x for x in self.server_uri if not x.bad ]
        if not servers:
            # NOTE: the only "bad" condition is an urllib3 LocationParseError (config typo)
            log.error("all servers are marked 'bad', aborting send")
            return

        # make sure meta_data is in a rational state.
        # (meta_data is written to disk alongside the payload(s) if
        # diskqueueing is enabled and the payloads are destined to disk, rather
        # than Splunk)
        meta_data = kwargs.get('meta_data')
        if not isinstance(meta_data, dict):
            meta_data = dict()
        for i in ('send_attempts', 'bad_request'):
            if i not in meta_data:
                meta_data[i] = 0

        # This logic is overly complicated originally the plan was to have the
        # HEC() object manage multiple servers and choose the successful one to
        # send to. Mostly if the hubble configs contain multiple endpoints,
        # hubble sends to all of them, not just the first successful one.  and
        # mostly that logic is handled outside of the HEC class (see
        # splunklogging.py)
        #
        # Below, we'll only send to one server, and we'll use the following plan:
        # for each server url in the HEC():
        # 1. if we get a message bundle to go through
        #    a. set fails to 0 (hey, it's working)
        #    b. don't try any more URLs
        #    c. if it's < 400, it's good, great return the result
        #    d. but if it's bad (==400 and "bad request"), then we're probably
        #       not going to succeed.  Log this horror and return the result,
        #       but make no attempt at disk-queueing (if applicable)
        # 2. if there's some exception during the send:
        #    a. log that something bad happened
        #    b. increment the fails (for sorting purposes only)
        #    c. consider the type of exception
        #       i. LocationParseError? This is never going to work. mark bad and continue
        #      ii. Some other Exception? This will probably work again some day, mark for queue
        #     iii. if nothing else succeeds or fails (as above); enter the
        #          message bundle to to the disk-queue (if any)

        possible_queue = False
        for server in sorted(servers, key=lambda u: u.fails):
            log.debug('trying to send %d octets to %s', len(data), server.uri)
            if server.outage:
                if server.outage.last_check_age < self.outage_recheck_time:
                    log.debug('flagged as having an outage, skipping send attempt')
                    possible_queue = True
                    continue
                else:
                    log.info('flagged as having an outage -- but it is time for a recheck')
                    server.outage.checking()
            try:
                # Remember that we tried to send this
                meta_data['send_attempts'] += 1
                r = self.pool_manager.request('POST', server.uri, body=data, headers=self.headers)
                server.fails = 0
                if server.outage:
                    server.outage = False
            except urllib3.exceptions.LocationParseError as e:
                log.error('server uri parse error "%s": %s', server.uri, e)
                server.bad = True
                continue
            except Exception as e:
                log.error('presumed minor error with "%s" (mark fail and continue): %s',
                    server.uri, repr(e), exc_info=True)
                possible_queue = True
                server.fails += 1
                if not server.outage and server.fails >= self.num_fails_indicate_outage:
                    log.info("flagging server outage (%d fails, %s)", server.fails, server.uri)
                    server.outage = True
                continue

            if r.status < 400:
                log.debug('octets accepted')
                return r

            elif r.status == 400 and r.reason.lower() == 'bad request':
                log.info('message not accepted (%d %s); incrementing bad_request counter',
                    r.status, r.reason)
                # try to queue the message if we don't find some other way to send it
                possible_queue = True
                # If Splunk said it doesn't want this message, increment the opinion counter
                meta_data['bad_request'] += 1
            elif r.status == 403:
                log.error('invalid or expired token (%d %s)', r.status, r.reason)
                possible_queue = True

        # if we get here and something above thinks a queue is a good idea
        # then queue it! \o/
        if possible_queue:
            log.debug('possible_queue indicated')

            if self.queue:
                # If we've already tried to send this more than max_queue_cycles times,
                # we consider that Splunk doesn't want it for some reason.
                if meta_data['send_attempts'] > self.max_queue_cycles:
                    log.error('dropping message that appears to have cycled more than %d times',
                        meta_data['send_attempts'])
                    return None

                # If Splunk actually says it doesn't want it more than
                # max_bad_request_cycles, we consider that Splunk may have actually
                # said so (and it wasn't just an opinionated load balancer or
                # something).
                if meta_data['bad_request'] > self.max_bad_request_cycles:
                    log.error('dropping message that Splunk said (%d times) it does not want',
                        meta_data['bad_request'])
                    return None

                # Drop these infos to disk.
                self._queue_event(data, meta_data=meta_data)
            else:
                log.debug('queue is NoQueue, not actually queueing anything')

    def _finish_send(self, r):
        if r is not None and hasattr(r, 'status') and hasattr(r, 'reason'):
            log.debug('_send() result: %d %s', r.status, r.reason)
            if self.queue:
                self.flushQueue()


    def sendEvent(self, payload, eventtime='', no_queue=False):
        payload = Payload.promote(payload, eventtime=eventtime, no_queue=no_queue)
        count_input(payload)
        r = self._send(payload)
        self._finish_send(r)


    def batchEvent(self, dat, eventtime='', no_queue=False):
        payload = Payload.promote(dat, eventtime, no_queue=False)

        if (self.currentByteLength + len(payload)) > self.maxByteLength:
            self.flushBatch()
            if http_event_collector_debug:
                log.debug('auto flushing')
        else:
            self.currentByteLength = self.currentByteLength + len(payload)
        count_input(payload)
        self.batchEvents.append(payload)


    def flushBatch(self):
        if self.batchEvents:
            r = self._send( *self.batchEvents )
            self.batchEvents = []
            self.currentByteLength = 0
            self._finish_send(r)

http_event_collector = HEC
