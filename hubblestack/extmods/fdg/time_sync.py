'''
Flexible Data Gathering: time_sync

This module checks the time of the host against some
NTP servers for differences bigger than 15 minutes.
'''


import logging
import salt.utils.platform

if not salt.utils.platform.is_windows():
    import ntplib
log = logging.getLogger(__name__)


def time_check(ntp_servers, max_offset=15, nb_servers=4,
               extend_chained=True, chained=None, chained_status=None):
    """
    Function that queries a list of NTP servers and checks if the
    offset is bigger than `max_offset` minutes. It expects the results from
    at least `nb_servers` servers in the list, otherwise the check fails.

    The first return value is True if no error has occurred in the process and False otherwise.
    The second return value is the result of the check:
        will be True only if at least `nb_servers` servers responded and none of them had an
        offset bigger than `max_offset` minutes;
        will be False if one of the servers returned an offset bigger than `max_offset` minutes
        or if not enough servers responded to the query;

    ntp_servers
        list of strings with NTP servers to query

    max_offset
        int telling the max acceptable offset in minutes - by default is 15 minutes

    nb_servers
        int telling the min acceptable number of servers that responded to the query
        - by default 4 servers

    extend_chained
        boolean determining whether to format the ntp_servers with the chained value or not

    chained
        The value chained from the previous call

    chained_status
        Status returned by the chained method.
    """
    if extend_chained:
        if ntp_servers:
            ntp_servers.extend(chained)
        else:
            ntp_servers = chained
    if not ntp_servers:
        log.error("No NTP servers provided")
        return False, None

    checked_servers = 0
    for ntp_server in ntp_servers:
        offset = _query_ntp_server(ntp_server)
        if not offset:
            continue
        # offset bigger than `max_offset` minutes
        if offset > max_offset * 60:
            return True, False
        checked_servers += 1
    if checked_servers < nb_servers:
        log.error("%d/%d required servers reached", checked_servers, nb_servers)
        return False, False

    return True, True


def _query_ntp_server(ntp_server):
    """
    Query the `ntp_server`, extracts and returns the offset in seconds.
    If an error occurs, or the server does not return the expected output -
    if it cannot be reached for example - it returns None.

    ntp_server
        string containing the NTP server to query
    """
    # use w32tm instead of ntplib
    if salt.utils.platform.is_windows():
        ret = __salt__['cmd.run']('w32tm /stripchart /computer:{0} /dataonly /samples:1'.format(
            ntp_server))
        try:
            return float(ret.split('\n')[-1].split()[1][:-1])
        except (ValueError, AttributeError, IndexError):
            log.error("An error occured while querying the server: %s", ret)
            return None

    ret = None
    try:
        ntp_client = ntplib.NTPClient()
        response = ntp_client.request(ntp_server, version=3)
        ret = response.offset
    except Exception:
        log.error("Unexpected error occured while querying the server.", exc_info=True)

    return ret
