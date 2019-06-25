
import re
import logging
import math
import hubblestack.status
import time

log = logging.getLogger(__name__)

__virtualname__ = 'hstatus'

SOURCETYPE = 'hubble_hec_summary'
MSG_COUNTS_PAT = r'hubblestack.hec.obj.input:(?P<stype>[^:]+)'

def __virtual__():
    return True

def msg_counts(pat=MSG_COUNTS_PAT, emit_self=False, sourcetype=SOURCETYPE):
    """ returns counter data formatted for the splunk_generic_return returner

        params:
            pat        - the key matching algorithm is a simple regular expression
                         (default: hstatus.MSG_COUNTS_PAT)
            emit_self  - whether to emit sourcetype counters (default: False)
            sourcetype - the sourcetype for the accounting messages (default: hstatus.SOURCETYPE)
    """

    # NOTE: any logging in here *will* mess up the summary count of hubble_log
    # (assuming hubble_log is reporting in and the logs are above the logging
    # level)

    summary_repeat = __opts__.get('hubble_status', {}).get('summary_repeat', 4)

    now = int(time.time())
    pat = re.compile(pat)
    ret = list() # events to return
    for bucket_set in hubblestack.status.HubbleStatus.short('all'):
        for k,v in bucket_set.iteritems():
            try:
                # should be at least one count
                if v['count'] < 1:
                    continue
            except KeyError as e:
                continue
            m = pat.match(k)
            if m:
                try:
                    stype = m.groupdict()['stype']
                except KeyError as e:
                    continue
                if emit_self or stype != sourcetype:
                    rep = hubblestack.status.HubbleStatus.get_reported(k, v['bucket'])
                    skip = False
                    if isinstance(rep, list):
                        if len(rep) < summary_repeat:
                            rep.append(now)
                        else:
                            skip = True
                    else:
                        # This is just in case the bucket can't be found
                        # it should otherwise always be populated as a list
                        rep = "unknown reported format: " + repr(rep)
                    if not skip:
                        ret.append({ 'stype': stype,
                            'bucket': v['bucket'],
                            'bucket_len': v['bucket_len'],
                            'reported': rep,
                            'event_count': v['count'],
                            'send_session_start': int(v['first_t']),
                            'send_session_end': int(math.ceil(v['last_t'])) })
    if ret:
        return { 'time': now, 'sourcetype': sourcetype, 'events': ret }

def dump():
    """ trigger a dump to the status.json file as described in hubblestack.status

        This is intended to be invoked from a daemon schedule and is probably
        not useful outside that context.
    """
    return hubblestack.status.HubbleStatus.dumpster_fire()
