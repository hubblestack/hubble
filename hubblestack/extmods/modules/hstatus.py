"""
Module that aggregates counter data for splunk_generic_return
and triggers a dump to status.json as invoked in the daemon.
"""
import re
import logging
import math
import time
import hubblestack.status

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
    ret = list()  # events to return
    for bucket_set in hubblestack.status.HubbleStatus.short('all'):
        for key, val in bucket_set.items():
            try:
                # should be at least one count
                if val['count'] < 1:
                    continue
            except KeyError:
                continue
            match = pat.match(key)
            if match:
                try:
                    stype = match.groupdict()['stype']
                except KeyError:
                    continue
                if emit_self or stype != sourcetype:
                    skip, rep = _get_reported(summary_repeat, now, key, val)
                    if not skip:
                        ret.append({'stype': stype,
                                    'bucket': val['bucket'],
                                    'bucket_len': val['bucket_len'],
                                    'reported': rep,
                                    'event_count': val['count'],
                                    'send_session_start': int(val['first_t']),
                                    'send_session_end': int(math.ceil(val['last_t']))})
    if ret:
        return {'time': now, 'sourcetype': sourcetype, 'events': ret}
    return None


def _get_reported(summary_repeat, now, key, val):
    """
    Helper function that returns the bucket.
    If its length is smaller than ``summary_rep``, skip it.
    """
    rep = hubblestack.status.HubbleStatus.get_reported(key, val['bucket'])
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
    return skip, rep


def dump():
    """ trigger a dump to the status.json file as described in hubblestack.status

        This is intended to be invoked from a daemon schedule and is probably
        not useful outside that context.
    """
    return hubblestack.status.HubbleStatus.dumpster_fire()
