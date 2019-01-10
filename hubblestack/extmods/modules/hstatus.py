
import re
import logging
import math
import hubblestack.status

log = logging.getLogger(__name__)

__virtualname__ = 'hstatus'

SOURCETYPE = 'hubble_audit_summary'

def __virtual__():
    return True

def get():
    ''' return the counters and timing status tracked by hubblestack.status

        (probably only useful from other excution modules)
    '''
    return hubblestack.status.HubbleStatus.stats()

def msg_counts(pat=r'hubblestack.hec.obj.input:(?P<stype>[^:]+)', reset=True):
    ''' returns counter data formatted for the splunk_generic_return returner

        params:
            pat   - the key matching algorithm is a simple regular expression
            reset - whether or not to reset the counters returned
    '''

    pat = re.compile(pat)
    ret = list() # events to return
    got_stats = get()
    fudge_me = None
    to_reset = set()
    for k,v in got_stats.iteritems():
        try:
            if v['first_t'] == 0 or v['last_t'] == 0:
                continue
        except KeyError:
            continue
        m = pat.match(k)
        if m:
            # first, populate d with {'stype': 'sourcetypehere'}
            d = m.groupdict()
            # then add the stats
            d.update({ 'event_count': v['count'], 'send_session_start': int(v['first_t']),
                'send_session_end': int(math.ceil(v['last_t'])) })
            ret.append(d)
            # keep a pointer to the hec_counters
            # they'll need to be fixed later
            if d['stype'] == SOURCETYPE:
                fudge_me = d
        to_reset.add(k)

    if ret:
        if reset:
            for k in to_reset:
                hubblestack.status.HubbleStatus.reset(k)
        min_time = min([ x['send_session_start'] for x in ret ])
        if fudge_me:
            # this is a fudge factor for the recursion where we report on own
            # sourcetype missing the currently-being-submitted counts
            fudge_me['event_count'] += len(ret)
        return { 'sourcetype': SOURCETYPE, 'time': min_time, 'events': ret }

def dump():
    ''' trigger a dump to the status.json file as described in hubblestack.status

        This is intended to be invoked from a daemon schedule and is probably
        not useful outside that context.
    '''
    hubblestack.status.HubbleStatus.dumpster_fire()
