
import re
import logging
import math
import hubblestack.status

log = logging.getLogger(__name__)

__virtualname__ = 'hstatus'

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
            pat - the key matching algorithm is a simple regular expression
    '''

    if reset:
        log.error("TODO: reset timers")

    km = re.compile(pat)
    r = list()
    s = get()
    fudge_me = None
    for k,v in s.iteritems():
        try:
            if v['first_t'] == 0 or v['last_t'] == 0:
                continue
        except KeyError:
            continue
        m = km.match(k)
        if m:
            d = m.groupdict()
            d.update({ 'count': v['count'], 'start': int(v['first_t']),
                'end': int(math.ceil(v['last_t'])) })
            r.append(d)
            if d['stype'] == 'hubble_hec_counters':
                fudge_me = d
    if r:
        min_time = min([ x['start'] for x in r ])
        if fudge_me:
            # this is a fudge factor for the recursion where we report on own
            # sourcetype missing the currently-being-submitted counts
            fudge_me['count'] += len(r)
        return { 'sourcetype': 'hubble_hec_counters', 'time': min_time, 'events': r }

def dump():
    ''' trigger a dump to the status.json file as described in hubblestack.status

        This is intended to be invoked from a daemon schedule and is probably
        not useful outside that context.
    '''
    hubblestack.status.HubbleStatus.dumpster_fire()
