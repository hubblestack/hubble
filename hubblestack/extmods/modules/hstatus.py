
import re
import logging
import math
import hubblestack.status

log = logging.getLogger(__name__)

__virtualname__ = 'hstatus'

SOURCETYPE = 'hubble_audit_summary'
MSG_COUNTS_PAT = r'hubblestack.hec.obj.input:(?P<stype>[^:]+)'

def __virtual__():
    return True

def msg_counts(pat=MSG_COUNTS_PAT, reset=True, emit_self=False, sourcetype=SOURCETYPE):
    ''' returns counter data formatted for the splunk_generic_return returner

        params:
            pat        - the key matching algorithm is a simple regular expression
                         (default: hstatus.MSG_COUNTS_PAT)
            reset      - whether or not to reset the counters returned (default: True)
            emit_self  - whether to emit sourcetype counters (default: False)
            sourcetype - the sourcetype for the accounting messages (default: hstatus.SOURCETYPE)
    '''

    pat = re.compile(pat)
    ret = list() # events to return
    to_reset = set()
    for k,v in hubblestack.status.HubbleStatus.stats().iteritems():
        try:
            # if this counter hasn't fired at all, skip it
            if v['first_t'] == 0 or v['last_t'] == 0:
                continue
            # Sometimes the very first loop will give a trivial
            # 1 second long count of exactly one event. Let's build up at least
            # a couple counts before we report/reset.
            if v['last_t'] <= v['first_t'] + 1:
                continue
            if v['event_count'] < 1:
                continue
        except KeyError:
            continue
        m = pat.match(k)
        if m:
            try:
                stype = m.groupdict()['stype']
            except KeyError:
                continue
            if emit_self or stype != sourcetype:
                ret.append({ 'stype': stype,
                    'event_count': v['count'],
                    'send_session_start': int(v['first_t']),
                    'send_session_end': int(math.ceil(v['last_t'])) })
            to_reset.add(k)

    if ret:
        if reset:
            for k in to_reset:
                hubblestack.status.HubbleStatus.reset(k)
        return { 'sourcetype': sourcetype, 'events': ret }

def dump():
    ''' trigger a dump to the status.json file as described in hubblestack.status

        This is intended to be invoked from a daemon schedule and is probably
        not useful outside that context.
    '''
    return hubblestack.status.HubbleStatus.dumpster_fire()
